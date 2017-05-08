try {
    conf = require('./conf.json')
}
catch(e) {
    console.log('App requires a conf.json file')
    process.exit(1)
}

cluster     = require('cluster')
http        = require('http')
logline     = require('./logline')
moment      = require('moment-timezone') // external
mysql       = require('mysql')           // external
nodemailer  = require('nodemailer')      // external
os          = require('os')
pagefactory = require('./pagefactory')
qs          = require('querystring')
url         = require('url')

var locks = {}

pool = mysql.createPool(conf.db)

pool.on('release', db => { // scan locks and delete the lock object which has db.threadId and any that are older than 2 seconds
    Object.keys(locks).map(ip => {
        if (locks[ip].threadId == db.threadId || locks[ip].ts < (Date.now() - 2000)) delete locks[ip]
    })
})

if (cluster.isMaster) {
    for (var i = 0; i < require('os').cpus().length; i++) cluster.fork();

    cluster.on('exit', function(worker, code, signal) {
        logline(__line, `worker pid ${worker.process.pid} died with code ${code} from signal ${signal}, replacing that worker`)
        cluster.fork()
    })
} else {
    http.createServer(run).listen(conf.http_port)
}

function run(req, res) {

    var state = { // start accumulation of state for this request
        page    : url.parse(req.url).pathname.split('/')[1] || 'home',
        queries : [],
        req     : req,
        res     : res,
    }

    var eh = create_err_handler(state)

    if (typeof pages[state.page] !== 'function') return eh({ code: 404, message: `No page like "${req.url}"` })

    connect_to_db(state)
        .then(block_countries)
        .then(block_nuked)
        .then(collect_post_data)
        .then(set_user)
        .then(pages[state.page])
        .catch(eh)
}

var pages = {

    home : state => {

        query('select * from addresses, zips where address_zip=zip_code order by address_modified desc', null, state,
            results => {
                state.message   = 'Increasing fair play for buyers and sellers'
                state.addresses = results
                send_html(200, pagefactory.render(state), state)
            }
        )
    },
        
    users : state => {

        try {
            var user_screenname = url.parse(state.req.url).path.split('/')[2].replace(/\W/g,'') // like /users/Patrick
            var sql   = 'select * from users where user_screenname=?'
            var parms = [user_screenname]
        }
        catch(e) {
            var sql   = 'select * from users'                                             // no username given, so show them all
            var parms = null
        }

        query(sql, parms, state,
            results => {
                state.users = results
                send_html(200, pagefactory.render(state), state)
            }
        )
    },

    about : state => {
        state.message = 'About whatdidyoubid.com'

        state.text = `Realtors routinely block or "lose" bids that do not give their own agency both sides of the commission. whatdidyoubid.com is a place
        where bidders can list what they bid for a house so that sellers and other bidders can get an idea of the degree to which this takes place.`

        send_html(200, pagefactory.render(state), state)
    },

    addressform : state => { send_html(200, pagefactory.render(state), state) },

    address : state => { // show a single address page

        // get address' db row number from url, eg 47 from /address/47/slug-goes-here
        var address_id = url.parse(state.req.url).path.split('/')[2].replace(/\D/g,'')

        query('select * from addresses, zips where address_id=? and address_zip=zip_code', [address_id], state,
            results => {
                if (0 == results.length) send_html(404, `No address with id "${address_id}"`, state)
                else {
                    state.address = results[0]

                    query('select * from comments left join users on comment_author=user_id where comment_address_id = ? order by comment_created',
                        [address_id], state,
                        results => { // now pick up the comment list for this address
                            if (results.length) state.comments = results
                            send_html(200, pagefactory.render(state), state)
                        }
                    )
                }
            }
        )
    },

    key_login : state => {

        key      = url.parse(state.req.url, true).query.key
        password = md5(Date.now() + conf.nonce_secret).substring(0, 6)

        // unfortunately a copy of home page sql
        query('select * from addresses, zips where address_zip=zip_code order by address_modified desc', null, state,
            results => {
                state.addresses     = results
                state.alert_content = `Your password is ${ password } and you are now logged in`
                state.message       = 'Increasing fair play for buyers and sellers'
                state.page          = 'home' // key_login generates home page html

                query('select user_email from users where user_key = ?', [key], state,
                    results => {
                        if (results.length) email = results[0].user_email
                        else {
                            message(`Darn, that key has already been used. Please try 'forgot password' if you need to log in.</a>`, state, state.res, state.db)
                            return
                        }

                        // erase key so it cannot be used again, and set new password
                        query('update users set user_key=null, user_md5pass=? where user_key=?', [md5(password), key], state,
                            results => { login(state.req, state.res, state, state.db, email, password) }
                        )
                    }
                )
            }
        )
    },

    post_login : state => {
        email    = state.post_data.email
        password = state.post_data.password

        login(state.req, state.res, state, state.db, email, password)
    },

    logout : state => {

        state.user = null
        var d      = new Date()
        var html   = pagefactory.render(state)

        var headers =  {
            'Content-Length' : html.length,
            'Content-Type'   : 'text/html',
            'Expires'        : d.toUTCString(),
            'Set-Cookie'     : `whatdidyoubid=_; Expires=${d}; Path=/`,
        }

        state.res.writeHead(200, headers)
        state.res.end(html)
        if (state.db) state.db.release()
    },

    registration : state => {

        Object.keys(state.post_data).map(key => { state.post_data[key] = strip_tags(state.post_data[key]) })

        if (/\W/.test(state.post_data.user_screenname)) { message('Please go back and enter username consisting only of letters', state, state.res, state.db); return }
        if (!/^\w.*@.+\.\w+$/.test(state.post_data.user_email)) { message('Please go back and enter a valid email address',  state); return }

        query('select * from users where user_email = ?', [state.post_data.user_email], state, results => {
            if (results[0]) {
                message(`That email is already registered. Please use the "forgot password" link above.</a>`, state)
                return
            }
            else {
                query('select * from users where user_screenname = ?', [state.post_data.user_screenname], state, results => {
                    if (results[0]) {
                        message(`That user name is already registered. Please choose a different one.</a>`, state)
                        return
                    }
                    else query('insert into users set ?', state.post_data, state, results => { send_login_link(state.req, state.res, state, state.db) })
                })
            }
        })
    },

    recoveryemail : state => {

        Object.keys(state.post_data).map(key => { state.post_data[key] = strip_tags(state.post_data[key]) })

        if (!/^\w.*@.+\.\w+$/.test(state.post_data.user_email)) { message('Please go back and enter a valid email address',  state); return }

        send_login_link(state.req, state.res, state, state.db)
    },

    postaddress : state => {

        post_data = state.post_data
        Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

        // do a bit of validation before inserting
        if (!/\d+\s+\w+/.test(post_data.address_num_street)) { message('Please go back and enter a valid street address', state); return }
        if (!/^\d\d\d\d\d$/.test(post_data.address_zip))     { message('Please go back and enter a five-digit zip code',  state); return }

        // if duplicate address, results.insertId will still be set correctly to existing address_id
        query('insert into addresses set ? on duplicate key update address_id=last_insert_id(address_id)', post_data, state,
            results => { redirect(`/address/${results.insertId}`, state.res, state.db) }
        )
    },

    postcomment : state => {

        post_data = state.post_data
        Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

        if (!post_data.comment_content) { send_html(200, '', state); return } // empty comment

        // rate limit by ip address
        query('select (now() - comment_created) as ago from comments where comment_author_ip = ? order by comment_created desc limit 1', [state.ip], state,
            results => {

                if (results.length && results[0].ago < 2) { // this ip already commented less than two seconds ago
                    state.page          = 'alert'
                    state.alert_content = 'You are posting comments too quickly! Please slow down.'
                    send_html(200, pagefactory.render(state), state)
                }
                else {

                    post_data.comment_author    = state.user ? state.user.user_id : 0
                    post_data.comment_author_ip = state.ip                            // so that ip gets inserted along with other post_data
                    post_data.comment_content   = post_data.comment_content.linkify() // linkify, imagify, etc

                    query('insert into comments set ?', post_data, state,
                        results => { // now select the inserted row so that we pick up the comment_created time and user data for displaying the comment
                            query('select * from comments left join users on comment_author=user_id where comment_id = ?', [results.insertId], state,
                                results => {
                                    if (results.length) state.comment = results[0]
                                    send_html(200, pagefactory.render(state), state)
                                }
                            )
                        }
                    )
                }
            }
        )
    },

    delete : state => { // delete a comment

        var comment_id = url.parse(state.req.url).path.split('/')[2].replace(/\D/g,'') // get comment db row number from url, eg 47 from /delete/47

        // check that current user has permission to delete this comment

        if (!state.user) send_html(200, pagefactory.render(state), state) // do nothing if not logged in

        // delete comment only if current user is comment_author
        query('delete from comments where comment_id = ? and comment_author = ?', [comment_id, state.user.user_id], state,
            results => {
                send_html(200, pagefactory.render(state), state)
            }
        )
    },

} /////////////////////////////////////// end of pages{} definition ///////////////////////////////////////

function connect_to_db(state) {

    return new Promise(function(fulfill, reject) {

		pool.getConnection(function(err, db) {

            if (err) throw {
                code    : 500,
                message : 'failed to get db connection',
            }

            state.db = db
			state.ip = state.req.headers['x-forwarded-for']

			// query or set a database lock for this ip; each ip is allowed only one outstanding connection at a time
			if (locks[state.ip]) { send_html(403, 'Rate Limit Exceeded', state); console.log('Rate limit exceeded by state.ip'); return }
			else {
				locks[state.ip] = { // set the lock
					threadId : db.threadId,
					ts       : Date.now()
				}
			}

            fulfill(state)
		})
    })
}

function block_countries(state) { // block entire countries like Russia because all comments from there are inevitably spam

    return new Promise(function(fulfill, reject) {

        query('select country_evil from countries where inet_aton(?) >= country_start and inet_aton(?) <= country_end', [state.ip, state.ip],
            state, results => {
                if (results.length && results[0].country_evil) throw { code : 404, message : 'Not Found', }
                fulfill(state)
            }
        )
    })
}

function block_nuked(state) { // block nuked users, usually spammers

    return new Promise(function(fulfill, reject) {

        query('select count(*) as c from nukes where nuke_ip_address = ?', [state.ip], state,
            results => {
                if (results[0].c) throw { code : 404, message : 'Not Found', }
                fulfill(state)
            }
        )
    })
}

function collect_post_data(state) { // if there is any POST data, accumulate it and append it to req object

    return new Promise(function(fulfill, reject) {

        if (state.req.method == 'POST') {
            var body = ''

            state.req.on('data', function (data) {
                body += data

                if (body.length > 1e6) { // too much POST data, kill the connection
                    state.req.connection.destroy()
                    throw { code : 413, message : 'Too much POST data', }
                }
            })

            state.req.on('end', function () {
                var post_data   = qs.parse(body)
                Object.keys(post_data).map(function(key) { post_data[key] = post_data[key].trim() }) // trim all top level values, should all be strings
                state.post_data = post_data
                fulfill(state)
            })
        }
        else fulfill(state)
    })
}

function set_user(state) { // update state with whether they are logged in or not

    // cookie is like whatdidyoubid=1_432d32044278053db427a93fc352235d where 1 is user and 432d... is md5'd password

    return new Promise(function(fulfill, reject) {

        try {
            var user_id      = state.req.headers.cookie.split('=')[1].split('_')[0]
            var user_md5pass = state.req.headers.cookie.split('=')[1].split('_')[1]

            query('select * from users where user_id = ? and user_md5pass = ?', [user_id, user_md5pass], state,
                results => {
                    if (0 == results.length) state.user = null
                    else                     state.user = results[0]

                    fulfill(state)
                }
            )
        }
        catch(e) { // no valid cookie
            state.user = null
            fulfill(state)
        }
    })
}

function login(req, res, state, db, email, password) {

    query('select * from users where user_email = ? and user_md5pass = ?', [email, md5(password)], state,
        results => {

            if (0 == results.length) {
                state.login_failed_email = email
                state.user               = null
                var user_id              = ''
                var user_md5pass         = ''
            }
            else {
                state.login_failed_email = null
                state.user               = results[0]
                var user_id              = state.user.user_id
                var user_md5pass         = state.user.user_md5pass
            }

            html = pagefactory.render(state)

            var cookie = `whatdidyoubid=${user_id}_${user_md5pass}`
            var d      = new Date()
            var decade = new Date(d.getFullYear()+10, d.getMonth(), d.getDate()).toUTCString()

            var headers =  {
                'Content-Length' : html.length,
                'Content-Type'   : 'text/html',
                'Expires'        : d.toUTCString(),
                'Set-Cookie'     : `${cookie}; Expires=${decade}; Path=/`, // do NOT use 'secure' or unable to test login in dev, w is http only
            }

            res.writeHead(200, headers)
            res.end(html)
            if (db) db.release()
        }
    )
}

function redirect(redirect_to, res, db) {

    var message = `Redirecting to ${ redirect_to }`

    var headers =  {
        'Location'       : redirect_to,
        'Content-Length' : message.length,
        'Expires'        : new Date().toUTCString()
    }

    res.writeHead(303, headers)
    res.end(message)
    if (db) db.release()
}

function message(message, state) {
    state.page    = 'message'
    state.message =  message
    send_html(200, pagefactory.render(state), state)
}

function send_html(code, html, state) {

    var headers =  {
        'Content-Type'   : 'text/html',
        'Content-Length' : html.length,
        'Expires'        : new Date().toUTCString()
    }

    state.res.writeHead(code, headers)
    state.res.end(html)
    if (state.db) state.db.release()
}

function md5(str) {
    var crypto = require('crypto')
    var hash = crypto.createHash('md5')
    hash.update(str)
    return hash.digest('hex')
}

function strip_tags(s) {
    return s.replace(/(<([^>]+)>)/g,'')
}

function get_transporter() {
    return nodemailer.createTransport({
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
}

function send_login_link(req, res, state, db) {

    baseurl  = (/localdev/.test(os.hostname())) ? 'http://dev.whatdidyoubid.com:8080' : 'https://whatdidyoubid.com' // for testing email
    key      = md5(Date.now() + conf.nonce_secret)
    key_link = `${ baseurl }/key_login?key=${ key }`

    query('update users set user_key=? where user_email=?', [key, state.post_data.user_email], state,
        results => {

            if (results.changedRows) {

                message('Please check your email for the login link', state, res, db)

                let mailOptions = {
                    from:    conf.admin_email,
                    to:      state.post_data.user_email,
                    subject: 'Your whatdidyoubid.com login info',
                    html:    `Click here to log in and get your password: <a href='${ key_link }'>${ key_link }</a>`
                }

                get_transporter().sendMail(mailOptions, (error, info) => {
                    if (error) { db.release(); throw error }
                    console.log('Message %s sent: %s', info.messageId, info.response);
                })
            }
            else message(`Could not find user with email ${ state.post_data.user_email }`, state, res, db)
        }
    )
}

String.prototype.linkify = function(ref) {

    var urlPattern = /\b(?:https?|ftp):\/\/[a-z0-9-+&@#\/%?=~_|!:,.;]*[a-z0-9-+&@#\/%=~_|]/gim; // http://, https://, ftp://

    var pseudoUrlPattern = /(^|[^\/])(www\.[\S]+(\b|$))/gim;                                    // www. sans http:// or https://

    var imagePattern = />((?:https?):\/\/[a-z0-9-+&@#\/%?=~_|!:,.;]*[a-z0-9-+&@#\/%=~_|]\.(jpg|jpeg|gif|gifv|png|bmp))</gim;

    var emailAddressPattern = /[\w.]+@[a-zA-Z_-]+?(?:\.[a-zA-Z]{2,6})+/gim;

    return this
        .replace(urlPattern,          '<a href="$&">$&</a>')
        .replace(pseudoUrlPattern,    '$1<a href="http://$2">$2</a>')
        .replace(imagePattern,        '><img src="$1"><') // it's already a link because of urlPattern above
        .replace(emailAddressPattern, '<a href="mailto:$&">$&</a>');
}

function query(sql, args, state, cb) {

    var q

    var get_results = function (error, results, fields, timing) {
        if (error) { state.db.release(); throw error }
        state.queries.push({
            sql : q.sql,
            ms  : timing
        })
        cb(results)
    }

    q = args ? state.db.query(sql, args, get_results)
             : state.db.query(sql,       get_results)
}

function create_err_handler(state) { // closure to pass back a promise rejection handler which has state in context

    return function(err) { // the actual rejection handler
        send_html(err.code, err.message, state)
    }
}
