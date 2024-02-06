// see here: https://ethereum.stackexchange.com/questions/4572/is-json-rpc-error-behavior-documented
// and here: http://xmlrpc-epi.sourceforge.net/specs/rfc.fault_codes.php

module.exports = {
    initPending:     {code: -31999, message: 'web3proxy initialization pending'},
    connectionError: {code: -31998, message: 'Connection to Node failed'},
    
    genericError:    {code: -32000, message: 'Unspecified Error'},
    evmException:    {code: -32016, message: 'The execution failed due to an exception.'}, //e.g. eth_estimateGas
    
    invalidRequest:  {code: -32600, message: 'Invalid Request'},
    invalidMethod:   {code: -32601, message: 'Invalid Method'},
    invalidParams:   {code: -32602, message: 'Invalid params'},
    internalError:   {code: -32603, message: 'Internal Error'},
    internalTimeout: {code: -32606, message: 'Infura internal timeout'}, //happens on infura for eth_call at times
}