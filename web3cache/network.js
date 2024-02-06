function sendjson(res,obj)
{
    res.set({
        'Content-Type':  'application/json; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma':        'no-cache',
        'Expires':       '0'
    })
    res.send(JSON.stringify(obj))
}

module.exports = {
  sendjson,
};
