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
mysql       = require('mysql')
nodemailer  = require('nodemailer')
os          = require('os')
pagefactory = require('./pagefactory')
qs          = require('querystring')
set_state   = require('./set_state')
url         = require('url')

transporter = nodemailer.createTransport({
    host:   conf.email_host,
    port:   conf.email_port,
    secure: false, // do not use TLS
    auth: {
        user: conf.email_user,
        pass: conf.email_pass
    },
    tls: {
        rejectUnauthorized: false // do not fail on invalid certs
    }
})

if (cluster.isMaster) {
    for (var i = 0; i < require('os').cpus().length; i++) cluster.fork();

    cluster.on('exit', function(worker, code, signal) {
        logline(__line, `worker pid ${worker.process.pid} died with code ${code} from signal ${signal}, replacing that worker`)
        cluster.fork()
    })
} else {

    http.createServer(handler).listen(conf.http_port)

    function handler(req, res) {

        var page = url.parse(req.url).pathname.split('/')[1].replace(/\W/g,'') || 'home'

        set_state.run(req, res, page)
    }
}
