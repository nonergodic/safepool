//web3proxy acts as an access-restriction and caching layer on top of the rpc node that's connected to the blockchain

const sendjson = require('./network').sendjson
const syslog   = require('./syslog')('web3proxy')
const rpcErrors = require('./rpcErrors')
const RpcNodes = require('./rpcNodes')

const mainRpcNode = process.env.WEB3PROXY_MAIN_URL || 'http://127.0.0.1:8545'
const fallbackRpcNode = process.env.WEB3PROXY_FALLBACK_URL

const pollLatestBlockInterval = 2*1000
const initializeRetryInterval = 10*1000
const cacheStatisticsLoggingInterval = 60*60*1000

//block buffers guard against underlying nodes not receiving newest blocks at the same time
const blockMaxGap = process.env.BLOCKMAXGAP || 12
const blockDelay = process.env.BLOCKDELAY || 2
const blockRetention = 3 //must be at least 1

//established during start up of the service
let init = {
    net_version: '',
    earliestBlockNumber: -1,
    completed: false,
    startedOn: new Date().toISOString(),
}

let lagged = {
    blockNumber: -1,
    delayedBlocks: new Map(),
    recentBlockHashes: new Map(),
}

let counters = {
    cacheResets: 0,
    //one counter per method
}

const rpcNodes = new RpcNodes(mainRpcNode, fallbackRpcNode, syslog.chunk.warn)

async function executeCall(method, params, requested = true) {
    if (requested)
        ++counters[method].misses
    
    const reply = await rpcNodes.send(method, params)

    if (reply === null)
        syslog.line.log("got null reply for", method, params)
    
    return reply
}

const toHex = num => '0x' + num.toString(16)

function normalizeBlockNumber(blockNumber) {
    if (blockNumber === 'latest')
        return lagged.blockNumber
    
    if (blockNumber === 'earliest' || blockNumber === '0x0' || blockNumber === '0')
        return init.earliestBlockNumber

    return parseInt(blockNumber)
}

/* javascript fucking sucks, all caching in here should be implemented using ordered maps, most recent access times, etc.
 * but since having simple utilities like sorted containers, backwards iteration, etc. is too much to ask for,
 * the current impl is much simpler and uses simple FIFO: It relies on map.set() inserting at the end of the container and
 * enforces size limits by deleting elements in the beginning...
 */
async function cacheUpsert(map, key, valGen, maxSize) {
    let val
    if (map.has(key)) {
        val = map.get(key)
        map.delete(key)
    }
    else
        val = (valGen instanceof Function) ? await valGen() : valGen
    
    if (val !== null)
        map.set(key, val)
    
    if (map.size > maxSize) //delete oldest entry
        map.delete(map.entries().next().value[0])
    
    return val
}

const web3Methods = {
    'net_version': {
        expectedParamsLength: 0,
        cleanCache: function() {},
        handleRequest: async function (params) {return init.net_version},
    },
    'eth_blockNumber': {
        expectedParamsLength: 0,
        cleanCache: function() {},
        handleRequest: async function (params) {return toHex(lagged.blockNumber)},
    },         
    'eth_getBlockByNumber': {
        expectedParamsLength: 2,
        cleanCache: function() {this.cache.clear()},
        handleRequest: async function (params) {
            if (params[1])
                throw [
                    rpcErrors.invalidParams,
                    'second param has to be false, only retrieval of transaction hashes is supported'
                ]

            const normBlockNum = normalizeBlockNumber(params[0])

            if (normBlockNum > lagged.blockNumber)
                return null
            
            return await cacheUpsert(
                this.cache,
                normBlockNum,
                () => executeCall('eth_getBlockByNumber', [toHex(normBlockNum), false]),
                this.maxCacheSize
            )
        },
        cache: new Map(),
        maxCacheSize: 20,
        cacheInsert: function(latestBlock) {
            cacheUpsert(this.cache, parseInt(latestBlock.number), latestBlock, this.maxCacheSize)
        },
    },
    'eth_getLogs': {
        expectedParamsLength: 1,
        cleanCache: function() {this.cache.clear()},
        handleRequest: async function (params) {
            let filterObj = params[0]

            if (!filterObj.fromBlock || !filterObj.toBlock)
                throw [rpcErrors.invalidParams, 'missing fromBlock and/or toBlock property']
            
            if (!filterObj.topics || filterObj.topics.length !== 1)
                throw [rpcErrors.invalidParams, 'only supports exactly one topic']
            
            const normFromBlockNum = normalizeBlockNumber(filterObj.fromBlock)
            let normToBlockNum = normalizeBlockNumber(filterObj.toBlock)
            if (normToBlockNum > lagged.blockNumber)
                normToBlockNum = lagged.blockNumber
            
            if (normFromBlockNum > normToBlockNum)
                return [] // happens e.g. when querying from last known blocknumber + 1 to latest
            
            const addr = filterObj.address ? filterObj.address.toLowerCase() : 'any'
            const topic = filterObj.topics[0]

            let cached
            cached = await cacheUpsert(this.cache,            topic, new Map(), this.maxTopicsSize)
            cached = await cacheUpsert(    cached,             addr, new Map(), this.maxAddrPerTopic)
            cached = await cacheUpsert(    cached, normFromBlockNum, new Map(), this.maxEntriesPerAddr)

            const tryCombiningLogs = async () => {
                filterObj.toBlock = toHex(normToBlockNum)
                
                let closestTo = -1
                for (const cachedTo of cached.keys())
                    if (closestTo < cachedTo && cachedTo < normToBlockNum)
                        closestTo = cachedTo
                
                filterObj.fromBlock = closestTo !== -1 ? toHex(closestTo + 1) : toHex(normFromBlockNum)
                const prevLogs = (closestTo !== -1) ? cached.get(closestTo) : []
                return prevLogs.concat(await executeCall('eth_getLogs', [filterObj]))
            }

            return await cacheUpsert(cached, normToBlockNum, tryCombiningLogs, this.maxLogsPerEntry)
        },
        cache: new Map(),
        maxTopicsSize: 10,
        maxAddrPerTopic: 20,
        maxEntriesPerAddr: 10,
        maxLogsPerEntry: 10,
    },
    'eth_getCode': {
        expectedParamsLength: 2,
        cleanCache: function() {
            this.cache.blockNumber = 0
            this.cache.noCode = {}
            this.cache.knownCode.clear()
        },
        handleRequest: async function (params) {
            const addr = params[0].toLowerCase()
            if (params[1] !== 'latest')
                throw [rpcErrors.invalidParams, 'only supports latest block']
            
            //implementation assumes that once code has been deployed to an address, it will not change anymore
            //might fail in case of smart contract self-destruction?

            if (this.cache.knownCode.has(addr)) {
                let code = this.cache.knownCode.get(addr)
                this.cache.knownCode.delete(addr)
                this.cache.knownCode.set(addr, code)
                return code
            }

            if (this.cache.blockNumber !== lagged.blockNumber) {
                this.cache.blockNumber = lagged.blockNumber
                this.cache.noCode = {}
            }
            else if (this.cache.noCode[addr])
                return "0x"
            
            const code = await executeCall('eth_getCode', [params[0], toHex(lagged.blockNumber)])
            if (code && code !== "0x")
                await cacheUpsert(this.cache.knownCode, addr, code, this.maxCacheSize)
            else
                this.cache.noCode[addr] = true

            return code
        },
        cache: {
            blockNumber: 0,
            noCode: {},
            knownCode: new Map(),
        },
        maxCacheSize: 100,
    },
    'eth_call': {
        expectedParamsLength: 2,
        cleanCache: function() {this.cache.clear()},
        handleRequest: async function (params) {
            const txObjStr = JSON.stringify(params[0]) //TODO order? might not be equivalent to deep compare
            const normBlockNum = normalizeBlockNumber(params[1])

            if (normBlockNum > lagged.blockNumber)
                return "0x"

            let cached = await cacheUpsert(this.cache, normBlockNum, new Map(), this.maxCacheSize)

            return await cacheUpsert(
                cached,
                txObjStr,
                () => executeCall('eth_call', [params[0], toHex(normBlockNum)]),
                this.maxCallsPerBlock
            )
        },
        cache: new Map(),
        maxCacheSize: 10,
        maxCallsPerBlock: 500,
    },
    'eth_estimateGas': {
        expectedParamsLength: 1,
        cleanCache: function() {this.cache.clear()},
        handleRequest: async function (params) {
            const txObjStr = JSON.stringify(params[0]) //TODO order? might not be equivalent to deep compare
            if (this.cache.has(txObjStr) && this.cache.get(txObjStr).blockNumber !== lagged.blockNumber)
                this.cache.delete(txObjStr)
            
            return (
                await cacheUpsert(
                    this.cache,
                    txObjStr,
                    async () => {
                        return {
                            blockNumber: lagged.blockNumber,
                            result: await executeCall('eth_estimateGas', params)
                        }
                    },
                    this.maxCacheSize
                )
            ).result
        },
        cache: new Map(),
        maxCacheSize: 50,
    },
    'eth_gasPrice': {
        expectedParamsLength: 0,
        cleanCache: function() {this.cache = {}},
        handleRequest: async function (params) {
            if (this.cache.blockNumber !== lagged.blockNumber)
                this.cache = {
                    blockNumber: lagged.blockNumber,
                    result: await executeCall('eth_gasPrice', [])
                }
            
            return this.cache.result
        },
        cache: {}
    },
    'eth_getBalance': {
        expectedParamsLength: 2,
        cleanCache: function() {this.cache.clear()},
        handleRequest: async function (params) {
            const addr = params[0].toLowerCase()
            const normBlockNum = normalizeBlockNumber(params[1])

            if (normBlockNum > lagged.blockNumber)
                return null
            
            let cached = await cacheUpsert(this.cache, normBlockNum, new Map(), this.maxCacheSize)

            return await cacheUpsert(
                cached,
                addr,
                () => executeCall('eth_getBalance', [params[0], toHex(normBlockNum)]),
                this.maxAddrPerBlock
            )
        },
        cache: new Map(),
        maxCacheSize: 20,
        maxAddrPerBlock: 200,
    },
    'eth_getTransactionByHash': {
        expectedParamsLength: 1,
        cleanCache: function() {this.cache.clear()},
        handleRequest: async function (params) {
            const txHash = params[0]

            return await cacheUpsert(
                this.cache,
                txHash,
                () => executeCall('eth_getTransactionByHash', params),
                this.maxCacheSize
            )
        },
        cache: new Map(),
        maxCacheSize: 5000,
    },
    'eth_getTransactionCount': {
        expectedParamsLength: 2,
        cleanCache: function() {this.cache.clear()},
        handleRequest: async function (params) {
            const addr = params[0].toLowerCase()
            if (params[1] !== 'latest')
                throw [rpcErrors.invalidParams, 'only supports latest block']
            
            if (this.cache.has(addr) && this.cache.get(addr).blockNumber !== lagged.blockNumber)
                this.cache.delete(addr)
            
            return (
                await cacheUpsert(
                    this.cache,
                    addr,
                    async () => {
                        return {
                            blockNumber: lagged.blockNumber,
                            result: await executeCall('eth_getTransactionCount', [params[0], toHex(lagged.blockNumber)])
                        }
                    },
                    this.maxCacheSize
                )
            ).result
        },
        cache: new Map(),
        maxCacheSize: 100,
    },
    'eth_getStorageAt': {
        expectedParamsLength: 3,
        cleanCache: function() {this.cache.clear()},
        handleRequest: async function (params) {
            const addrSlot = params[0].toLowerCase() + params[1]
            const normBlockNum = normalizeBlockNumber(params[2])

            if (normBlockNum > lagged.blockNumber)
                return "0x"

            let cached = await cacheUpsert(this.cache, normBlockNum, new Map(), this.maxCacheSize)
                
            return await cacheUpsert(
                cached,
                addrSlot,
                () => executeCall('eth_getStorageAt', [params[0], params[1], toHex(normBlockNum)]),
                this.maxReadsPerBlock
            )
        },
        cache: new Map(),
        maxCacheSize: 20,
        maxReadsPerBlock: 100,
    },
}

for (const method in web3Methods) {
    if (web3Methods.hasOwnProperty(method)) {
        counters[method] = {
            requests: 0,
            misses: 0,
        }
    }
}

async function noThrowSleepLoop(func, delay) {
    const msleep = async (ms) => new Promise(resolve => setTimeout(resolve, ms))
    while (true) {
        try {
            if (!await func())
                break
        }
        catch (e) {
            syslog.chunk.error(func.name + '(): caught exception:\n', e)
        }
        await msleep(delay)
    }
}

async function getBlockRange(start, count) {
    let proms = []
    for (let i = 0; i < count; ++i)
        proms.push(executeCall('eth_getBlockByNumber', [toHex(start+i), false], false))
        
    return await Promise.all(proms)
}

async function resetAndRefill() {
    async function impl() {
        const latestBlock = await executeCall('eth_getBlockByNumber', ['latest', false], false)
        const latestBlockNumber = parseInt(latestBlock.number)
        const oldestRecentNumber = latestBlockNumber - blockRetention - blockDelay + 1
        const blockCandidates = await getBlockRange(oldestRecentNumber, blockRetention)
        let consistent = true
        for (let i = 1; i < blockRetention; ++i) 
            if (blockCandidates[i].parentHash !== blockCandidates[i-1].hash) {
                consistent = false
                break
            }
        
        if (consistent) {
            for (const method in web3Methods)
                if (web3Methods.hasOwnProperty(method))
                    web3Methods[method].cleanCache()

            lagged.recentBlockHashes.clear()
            lagged.delayedBlocks.clear()

            for (const block of blockCandidates) {
                web3Methods['eth_getBlockByNumber'].cacheInsert(block)
                lagged.recentBlockHashes.set(parseInt(block.number), block.hash)
            }
            lagged.blockNumber = latestBlockNumber - blockDelay
            return false //stop retry loop
        }

        return true //keep trying
    }

    await noThrowSleepLoop(impl, pollLatestBlockInterval)
}

async function pollLatestBlock() {
    //false return means chain reorg detected -> clear cache
    async function handleLatestBlock() {

        function insertIntoDelayed(block) {
            const blockNumber = parseInt(block.number)
            if (!lagged.delayedBlocks.has(blockNumber))
                lagged.delayedBlocks.set(blockNumber, new Map())
            
            if (!lagged.delayedBlocks.get(blockNumber).has(block.hash))
                lagged.delayedBlocks.get(blockNumber).set(block.hash, block)
        }

        const latestBlock = await executeCall('eth_getBlockByNumber', ['latest', false], false)
        const latestBlockNumber = parseInt(latestBlock.number)
        if (latestBlockNumber <= lagged.blockNumber) {
            if (!lagged.recentBlockHashes.has(latestBlockNumber))
                syslog.line.log("Strange Chain Reorg: latestBlock much lower than expected!",
                                 "lagged.blockNumber:", lagged.blockNumber, "latestBlockNumber:", latestBlockNumber)
            else if (lagged.recentBlockHashes.get(latestBlockNumber) !== latestBlock.hash)
                syslog.line.log("Chain Reorg: blockHash of already processed block changed")
            else
                return true

            return false
        }

        if (latestBlockNumber > (lagged.blockNumber + blockMaxGap + blockDelay)) {
            syslog.line.log("Unexpectedly large gap in block numbers!",
                            "lagged.blockNumber:", lagged.blockNumber, "latestBlockNumber:", latestBlockNumber)
            return false
        }

        insertIntoDelayed(latestBlock)
        
        const catchUpCount = latestBlockNumber - lagged.blockNumber - blockDelay
        if (catchUpCount > 0) {
            //if there is any gap in delayedBlocks, just request a full range
            for (let i = 0; i < catchUpCount; ++i)
                if (!lagged.delayedBlocks.has(lagged.blockNumber+1 + i)) {
                    (await getBlockRange(lagged.blockNumber+1, catchUpCount)).forEach(block => insertIntoDelayed(block))
                    break
                }

            //try to find a consistent range            
            const ldb = offset => lagged.delayedBlocks.get(lagged.blockNumber + offset)
            const mostRecentHash = lagged.recentBlockHashes.get(lagged.blockNumber)

            //console.log("consistent range: catchUpCount:", catchUpCount, "lagged.blockNumber:", lagged.blockNumber, "\nrecentHashes:\n", lagged.recentBlockHashes)
            //lagged.delayedBlocks.forEach(numMap => numMap.forEach(block => console.log(parseInt(block.number), block.hash, block.parentHash)))

            for (const block of ldb(catchUpCount).values()) {
                //console.log("consistent range: considering block:", parseInt(block.number), block.hash, block.parentHash)
                let parentHash = block.parentHash
                let hashes = [block.hash]
                for (let i = catchUpCount-1; i > 0 && parentHash; --i) {
                    hashes.unshift(parentHash)
                    parentHash = (ldb(i).has(parentHash)) ? ldb(i).get(parentHash).parentHash : null
                }

                if (parentHash && mostRecentHash === parentHash) {
                    for (const hash of hashes) {
                        ++lagged.blockNumber
                        lagged.recentBlockHashes.delete(lagged.blockNumber-blockRetention)
                        lagged.recentBlockHashes.set(lagged.blockNumber, hash)
                        lagged.delayedBlocks.delete(lagged.blockNumber)
                    }

                    return true
                }
            }
            
            //failed to find a consistent range - check if recent block has changed
            const successors = lagged.delayedBlocks.get(lagged.blockNumber+1)
            for (const successor of successors.values())
                if (successor.parentHash !== mostRecentHash)
                    successors.delete(successor.hash)
            
            //if we don't have any viable successors to the most recent block, see if the most recent block itself changed
            if (!successors.size && 
                (await executeCall('eth_getBlockByNumber', [toHex(lagged.blockNumber), false], false)).hash !== mostRecentHash
                ) {
                syslog.line.log("Chain Reorg: blockHash of most recent block has changed")
                return false
            }

            //most recent block is still valid, but no consistent range - wait until next tick and try again
        }

        return true
    }

    if (!await handleLatestBlock()) {
        syslog.line.log("Resetting Cache")
        ++counters.cacheResets
        await resetAndRefill()
    }
    
    return true //always keep repeating
}

async function initialize() {
    syslog.line.log("using", mainRpcNode, "as main RPC node")
    if (fallbackRpcNode)
        syslog.line.log("using", fallbackRpcNode, "as fallback RPC node")
    else 
        syslog.line.warn("no fallback RPC node specified")
    
    init.net_version = await executeCall('net_version', [], false)
    init.earliestBlockNumber = parseInt((await executeCall('eth_getBlockByNumber', ['earliest', false], false)).number)
    await resetAndRefill()
    
    init.completed = true
    syslog.line.log("initialization complete")
    noThrowSleepLoop(pollLatestBlock, pollLatestBlockInterval) //no await on purpose! start main polling loop
    return false //stop retry loop
}

async function handleRpcRequest(request) {
    let response = {
        jsonrpc: '2.0',
        id: (request && request.id) ? request.id : null
    }

    try {
        if (!request || !(typeof request.method === 'string' || request.method instanceof String) ||
                !Array.isArray(request.params) || !request.id)
            throw [rpcErrors.invalidRequest]
        
        if (!web3Methods.hasOwnProperty(request.method))
            throw [rpcErrors.invalidMethod]
        
        if (web3Methods[request.method].expectedParamsLength !== request.params.length)
            throw [rpcErrors.invalidParams, 'expected ' + web3Methods[request.method].expectedParamsLength.toString() +
                   ' params, but only got ' + request.params.length.toString()]
            
        if (!init.completed)
            throw [rpcErrors.initPending]
        
        ++counters[request.method].requests

        response.result = await web3Methods[request.method].handleRequest(request.params)
    }
    catch (e) {        
        if (Array.isArray(e) && e.length && typeof e[0].code !== "undefined")
            response.error = {
                code: e[0].code,
                message: e[0].message || "",
                data: 'request:' + JSON.stringify(request) + ', node-data: ' + e[0].data + ', proxy-data: ' + e[1]
            }
        else {
            syslog.chunk.error("Caught unexpected exception in handleRpcRequest():\n", e,
                               "\nwhile processing request:\n", JSON.stringify(request,null,2),
                               '\nstate of cache:\n', JSON.stringify(lagged,null,2))
            
            response.error = {
                code: rpcErrors.internalError.code,
                message: rpcErrors.internalError.message,
                data: "server time of error: " + (new Date()).toISOString()
            }
        }
    }

    return response
}

function logCacheStatistics() {
    let syslogLines = ['Cache Statistics:']
    const printRow = (method, percentage, requests) => 
        syslogLines.push(method.padStart(25) + percentage.padStart(6) + requests.padStart(8))

    let totalMisses = 0
    let totalRequests = 0
    
    printRow('Method', 'Hit %', 'Requests')
    for (const method in web3Methods) {
        if (web3Methods.hasOwnProperty(method)) {
            printRow(
                method,
                Math.round(((counters[method].requests - counters[method].misses) / counters[method].requests)*100).toString(),
                counters[method].requests.toString()
            )
            totalMisses += counters[method].misses
            totalRequests += counters[method].requests
        }   
    }
    printRow('TOTAL', Math.round(((totalRequests - totalMisses) / totalRequests)*100).toString(), totalRequests.toString())
    syslogLines.push('Start of service: ' + init.startedOn)
    syslogLines.push('Cache resets since start of service: ' + counters.cacheResets.toString())
    syslog.line.log(syslogLines.join('\n'))

    return true
}

noThrowSleepLoop(initialize, initializeRetryInterval)
noThrowSleepLoop(logCacheStatistics, cacheStatisticsLoggingInterval)

async function web3proxy(req, res) {
    try {
        let responsePayload
        if (Array.isArray(req.body)) {
            responsePayload = []
            for (const rpcRequest of req.body)
                responsePayload.push(await handleRpcRequest(rpcRequest))
        }
        else
            responsePayload = await handleRpcRequest(req.body)

        res.set({'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true'})
        sendjson(res, responsePayload)
    }
    catch (e) {
        syslog.chunk.error('FATAL '.repeat(10)+ 'caught unexpected exception:', e)
    }
}

module.exports = web3proxy
