try {
    conf = require('./conf.json')
}
catch(e) {
    console.log('App requires a conf.json file in same dir as app.js')
    process.exit(1)
}

cluster     = require('cluster')
http        = require('http')
logline     = require('./logline')
moment      = require('moment-timezone')
mysql       = require('mysql')
nodemailer  = require('nodemailer')
os          = require('os')
pagefactory = require('./pagefactory')
qs          = require('querystring')
set_state   = require('./set_state')
url         = require('url')

if (cluster.isMaster) {
    for (var i = 0; i < require('os').cpus().length; i++) cluster.fork();

    cluster.on('exit', function(worker, code, signal) {
        logline(__line, `worker pid ${worker.process.pid} died with code ${code} from signal ${signal}, replacing that worker`)
        cluster.fork()
    })
} else {

    http.createServer(handler).listen(conf.http_port)

    function handler(req, res) {
        var page = url.parse(req.url).pathname.split('/')[1] || 'home'
        set_state.run(req, res, page)
    }
}
