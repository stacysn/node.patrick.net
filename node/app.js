try {
    conf = require(process.argv[2])
}
catch (e) {
    console.log('Please start this app with a config file, like this: "node app.js ./conf.json"')
    process.exit(1)
}

cluster     = require('cluster')
http        = require('http')
logline     = require('./logline')
mysql       = require('mysql')
pagefactory = require('./pagefactory')
set_state   = require('./set_state')
url         = require('url')

var pool = mysql.createPool(conf.db)

if (cluster.isMaster) {

    for (var i = 0; i < require('os').cpus().length; i++) cluster.fork();

    cluster.on('exit', function(worker, code, signal) {
        logline(__line, `worker pid ${worker.process.pid} died with code ${code} from signal ${signal}, restarting one`)
        cluster.fork()
    })
} else {

    http.createServer(handler).listen(conf.http_port)

    function handler(req, res) {

        var path = url.parse(req.url).path
        var page = path.split('/')[1].replace(/\W/g,'') || 'home'

        if (typeof set_state[page] === 'function') set_state[page](req, res, page, pool)
        else res.end()
    }
}
