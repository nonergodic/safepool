const fetch = require('node-fetch')
const rpcErrors = require('./rpcErrors')

function stringifyException(e) { //TODO replace with a more canonical solution
    if (typeof e ==="string")
        return e;
    
    if ( (typeof e.name === 'undefined' || e.name === 'Error') && 
         typeof e.constructor !== 'undefined' &&
         typeof e.constructor.name !== 'undefined' &&
         e.constructor.name !== 'Object'
       )
        e.name = e.constructor.name;

    if (e.name === 'RuntimeTypeError') // avoid data leaking
        e.message = e.message.split('\n')[0];

    let eobj = Object.assign({}, e);

    // cannot enumerate the contents of e, so do this instead
    for(const k of ['name','message','description'])
        if (typeof e[k] !== 'undefined')
            eobj[k] = e[k];

    return JSON.stringify(eobj);
}

/* round robin for main nodes
 * if a main node has failed, round robin among fallback nodes
 * if all fallback nodes have failed, try other main node as last resort
 *   --> dangerous because suddenly all load goes to a single eth node
 * 
 * example: 2 main nodes, 2 fallback nodes
 * while both main nodes are up, requests alternate between the two, fallback nodes are never queried
 * if main node 2 goes down:
 *   first request -> main node 1
 *   second request -> main node 2 (fails) -> fallback node 1
 *   third request -> main node 1
 *   fourth request -> main node 2 (skipped) -> fallback node 2
 * 
 * if a main node 2 and fallback 2 go down:
 *   first request -> main node 1
 *   second request -> main node 2 (fails) -> fallback node 1 (fails) -> fallback node 2
 *   third request -> main node 1
 *   fourth request -> main node 2 (skipped) -> fallback node 1 (skipped) -> fallback node 2
 * if fallback node 2 goes down too, all traffic would be routed to main node 1
 */
class RpcNodes {
    constructor(mainNodeUrls, fallbackNodeUrls = [], loggingCallback = () => {}) {
        if (!mainNodeUrls)
            throw Error("requires the url of at least one main RPC node");
        
        if (typeof mainNodeUrls === "string")
            mainNodeUrls = [mainNodeUrls];
        
        if (typeof fallbackNodeUrls === "string")
            fallbackNodeUrls = fallbackNodeUrls ? [fallbackNodeUrls] : [];
        
        this._log = loggingCallback;
        this._callId = 1;

        const toNodeStruct = (url, isMain) => ({
            url,
            isMain,
            failCount: 0,
            skipUntil: 0,
        });
        this._mainNodes = mainNodeUrls.map(url => toNodeStruct(url, true));
        this._fallbackNodes = fallbackNodeUrls.map(url => toNodeStruct(url, false));
        
        this._mainIndex = 0;
        this._fallbackIndex = 0;
    }

    async _query(node, method, params) {
        if (node.isMain)
            this._mainIndex = (this._mainIndex+1) % this._mainNodes.length;
        else
            this._fallbackIndex = (this._fallbackIndex+1) % this._fallbackNodes.length;

        const body = JSON.stringify({jsonrpc: '2.0', method, params, id: this._callId++});
        const completeRequest = {
            body:        body, // must match 'Content-Type' header
            cache:       'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
            credentials: 'same-origin', // include, same-origin, *omit
            headers: {
                'user-agent': 'Web3 Proxy',
                'content-type': 'application/json'
            },
            method:   'POST', // *GET, POST, PUT, DELETE, etc.
            mode:     'cors', // no-cors, cors, *same-origin
            redirect: 'follow', // manual, *follow, error
            referrer: 'no-referrer', // *client, no-referrer
        };
        
        let rpcResponse
        try {
            try {
                const fetchRet = await fetch(node.url, completeRequest);
                try {
                    rpcResponse = await fetchRet.json();
                }
                catch (ignore) {
                    throw fetchRet;
                }
            }
            catch (e) {
                throw [rpcErrors.connectionError, stringifyException(e)];
            }

            if (typeof rpcResponse.error === 'undefined' && typeof rpcResponse.result === 'undefined')
                throw [rpcErrors.internalError, 'rpc response misses result property: ' + JSON.stringify(rpcResponse)];

            if (node.failCount) {
                node.failCount = 0;
                node.skipUntil = 0;
            }
        }
        catch (e) {
            ++node.failCount;
            //linearly increase wait time in between consecutive failed attempts
            node.skipUntil = Date.now() + Math.min(node.failCount*5, 600)*1000;

            throw e;
        }

        if (typeof rpcResponse.error !== 'undefined')
            throw [rpcResponse.error];

        return rpcResponse.result;
    }

    async send(method, params) {
        const noThrowQuery = (node, attempt = 0) => this._query(node, method, params).then(
            result => ({node, result, attempt}),
            error => ({node, error, attempt})
        );
        
        const startMainIndex = this._mainIndex;
        const startFallbackIndex = this._fallbackIndex;

        let consideredMainCount = 0;
        let consideredFallbackCount = 0;
        
        let queryResults = [];
        while (true) {
            let queries = [];

            for (const qres of queryResults) {
                if (typeof qres.result !== "undefined")
                    return qres.result;

                if ([rpcErrors.connectionError.code, rpcErrors.internalError.code].includes(qres.error[0].code) ||
                    qres.error[0].code === rpcErrors.internalTimeout.code && qres.attempt
                   )
                    this._log("querying", qres.node.isMain ? "main" : "fallback", "node", qres.node.url, "failed.\n",
                              "error:", qres.error, "\nto request:\n", method, params,
                              "\nskipping node until:", new Date(qres.node.skipUntil).toISOString());
                else if (qres.error[0].code === rpcErrors.internalTimeout.code && !qres.attempt)
                   queries.push(noThrowQuery(qres.node, qres.attempt+1));
                else
                   throw qres.error;
            }

            while (true) {
                let curNode = null;
                if (!consideredMainCount)
                    curNode = this._mainNodes[startMainIndex];
                else if (consideredFallbackCount < this._fallbackNodes.length)
                    curNode = this._fallbackNodes[(startFallbackIndex + consideredFallbackCount) % this._fallbackNodes.length];
                else if (consideredMainCount < this._mainNodes.length)
                    curNode = this._mainNodes[(startMainIndex + consideredMainCount) % this._mainNodes.length];
                
                if (!curNode)
                    break;

                curNode.isMain ? ++consideredMainCount : ++consideredFallbackCount;
                
                if (Date.now() > curNode.skipUntil)
                    queries.push(noThrowQuery(curNode));

                if (!curNode.failCount)
                    break;
            }

            if (!queries.length) {
                //if all nodes are down, set current main node to be retried on next request ...
                //... so that at least there is always one node being queried per request
                this._mainNodes[startMainIndex].failCount = 0;
                this._mainNodes[startMainIndex].skipUntil = 0;
                throw [rpcErrors.connectionError, "Connection to all nodes failed"];
            }
            
            queryResults = await Promise.all(queries);
        }
    }
}

module.exports = RpcNodes