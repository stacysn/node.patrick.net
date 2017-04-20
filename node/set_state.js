var pages = {}
var locks = {}

pool = mysql.createPool(conf.db)

pool.on('release', function (db) { // scan locks and delete the lock object which has db.threadId and any that are older than 2 seconds
    Object.keys(locks).map(ip => {
        if (locks[ip].threadId == db.threadId || locks[ip].ts < (Date.now() - 2000)) delete locks[ip]
    })
})

exports.run = function (req, res, page) {

    var state = {} // start accumulation of state
    state.page = page

    if (typeof pages[page] !== 'function') { send_html(404, `No page like "${req.url}"`, res, null); return }

    connect_to_db(req, res, state)
}

pages.home = function (req, res, state, db) {

    var query = db.query('select * from addresses, zips where address_zip=zip_code', function (error, results, fields) {
        if (error) { db.release(); throw error }

        state.message   = 'Increasing fair play for buyers and sellers'
        state.addresses = results

        send_html(200, pagefactory.render(state), res, db)
    })
}

pages.users = function (req, res, state, db) {
    state.message = 'Users list not implemented yet'
    send_html(200, pagefactory.render(state), res, db)
}

pages.about = function (req, res, state, db) {
    state.message = 'About whatdidyoubid.com'

    state.text = `Realtors routinely block or "lose" bids that do not give their own agency both sides of the commission. whatdidyoubid.com is a place
    where bidders can list what they bid for a house so that sellers and other bidders can get an idea of the degree to which this takes place.`

    send_html(200, pagefactory.render(state), res, db)
}

pages.registerform = function (req, res, state, db) { send_html(200, pagefactory.render(state), res, db) }

pages.lostpwform = function (req, res, state, db) {

    state.email = url.parse(req.url, true).query.email

    send_html(200, pagefactory.render(state), res, db)
}

pages.addressform = function (req, res, state, db) { send_html(200, pagefactory.render(state), res, db) }

pages.address = function (req, res, state, db) { // show a single address page

    var address_id = url.parse(req.url).path.split('/')[2].replace(/\D/g,'') // get address' db row number from url, eg 47 from /address/47/slug-goes-here

    var query = db.query('select * from addresses, zips where address_id=? and address_zip=zip_code', [address_id], function (error, results, fields) {
        if (error) { db.release(); throw error }

        if (0 == results.length) send_html(404, `No address with id "${address_id}"`, res, null)
        else {
            state.address      = results[0]

            // now pick up the comment list for this address
            var query = db.query('select * from comments where comment_address_id = ? order by comment_created', [address_id],
                function (error, results, fields) {
                    if (error) { db.release(); throw error }

                    if (results.length) state.comments = results // if none, we will handle that in comment_list()

                    send_html(200, pagefactory.render(state), res, db)
            })
        }
    })
}

pages.key_login = function (req, res, state, db) { // erase key so it cannot be used again, and set new password

    key           = url.parse(req.url, true).query.key
    password      = md5(Date.now() + conf.nonce_secret).substring(0, 6)
    state.message = `Your password is ${ password } and you are now logged in`

    var query = db.query('select user_email from users where user_key = ?', [key],
        function (error, results, fields) {

            if (error) { db.release(); throw error }

            if (results.length) email = results[0].user_email
            else {
                message(`Darn, that key has already been used. Please <a href='/lostpwform'>reset password</a>`, state, res, db)
                return
            }

            var query = db.query('update users set user_key=null, user_md5pass=? where user_key=?', [md5(password), key],
                function (error, results, fields) {

                    if (error) {
                        message('Darn, something went wrong', state, res, db)
                        return
                    }

                    login(req, res, state, db, email, password)
                })
        })
}

pages.post_login = function (req, res, state, db) {
    email    = state.post_data.email
    password = state.post_data.password

    login(req, res, state, db, email, password)
}

pages.logout = function (req, res, state, db) {

    state.user = null
    var d      = new Date()
    var html   = pagefactory.render(state)

    var headers =  {
        'Content-Length' : html.length,
        'Content-Type'   : 'text/html',
        'Expires'        : d.toUTCString(),
        'Set-Cookie'     : `whatdidyoubid=_; Expires=${d}; Path=/`,
    }

    res.writeHead(200, headers)
    res.end(html)
    if (db) db.release()
}

pages.registration = function (req, res, state, db) {

    Object.keys(state.post_data).map(key => { state.post_data[key] = strip_tags(state.post_data[key]) })

    if (/\W/.test(state.post_data.user_screenname)) {
        message('Please go back and enter username consisting only of letters', state, res, db); return
    }

    if (!/^\w.*@.+\.\w+$/.test(state.post_data.user_email)) {
        message('Please go back and enter a valid email address',  state, res, db); return
    }

    var query = db.query('insert into users set ?', state.post_data,
        function (error, results, fields) {

            if (error) {
                if (/ER_DUP_ENTRY/.test(error.message))
                    message(`That user is already registered. <a href='/lostpwform?email=${ state.post_data.user_email }'>reset password</a>`, state, res, db)
                else
                    message('Darn, something went wrong', state, res, db)

                return
            }
            send_login_link(req, res, state, db)
        })
}

pages.recoveryemail = function (req, res, state, db) {

    Object.keys(state.post_data).map(key => { state.post_data[key] = strip_tags(state.post_data[key]) })

    if (!/^\w.*@.+\.\w+$/.test(state.post_data.user_email)) {
        message('Please go back and enter a valid email address',  state, res, db); return
    }

    send_login_link(req, res, state, db)
}


pages.postaddress = function (req, res, state, db) {

    post_data = state.post_data
    Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

    // do a bit of validation before inserting
    if (!/\d+\s+\w+/.test(post_data.address_num_street)) { message('Please go back and enter a valid street address', state, res, db); return }
    if (!/^\d\d\d\d\d$/.test(post_data.address_zip))     { message('Please go back and enter a five-digit zip code',  state, res, db); return }

    // if duplicate address, results.insertId will still be set correctly to existing address_id
    var query = db.query('insert into addresses set ? on duplicate key update address_id=last_insert_id(address_id)', post_data,
        function (error, results, fields) {
            if (error) { db.release(); throw error }
            redirect(`/address/${results.insertId}`, res, db)
        })
}

pages.postcomment = function (req, res, state, db) {

    post_data = state.post_data
    Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

    if (!post_data.comment_content) {
        send_html(200, '', res, db) 
        return
    }

    post_data.comment_author_ip = state.ip

    // rate limit by ip address
    var query = db.query('select (now() - comment_created) as ago from comments where comment_author_ip = ? order by comment_created desc limit 1',
        [post_data.comment_author_ip],
        function (error, results, fields) {
            if (error) { db.release(); throw error }

            if (results.length && results[0].ago < 2) { // this ip already commented less than two seconds ago
                state.page          = 'alert'
                state.alert_content = 'You are posting comments too quickly! Please slow down.'
                send_html(200, pagefactory.render(state), res, db)
            }
            else {
                var query = db.query('insert into comments set ?', post_data, function (error, results, fields) {
                    if (error) { db.release(); throw error }

                    // now select the inserted row so that we pick up the comment_created time for displaying the comment
                    var query = db.query('select * from comments where comment_id = ?', [results.insertId],
                        function (error, results, fields) {
                            if (error) { db.release(); throw error }

                            if (results.length) state.comment = results[0]

                            send_html(200, pagefactory.render(state), res, db)
                    })
                })
            }
        })
}

//////////////////////////////////////// end of pages; helper functions below ////////////////////////////////////////

function connect_to_db(req, res, state) {
    pool.getConnection(function(err, db) {
        if (err) throw err

        state.ip = req.headers['x-forwarded-for']

        // query or set a database lock for this ip; each ip is allowed only one outstanding connection at a time
        if (locks[state.ip]) { send_html(403, 'Rate Limit Exceeded', res, db); return }
        else { // set the lock
            locks[state.ip] = {
                threadId : db.threadId,
                ts       : Date.now()
            }
        }

        block_evil(req, res, state, db)
    })
}

function block_evil(req, res, state, db) {
    // block entire countries like Russia because all comments from there are inevitably spam
    db.query('select country_evil from countries where inet_aton(?) >= country_start and inet_aton(?) <= country_end', [state.ip, state.ip],
             function (error, results, fields) {

        if (error)                                     { db.release(); throw error }
        if (results.length && results[0].country_evil) { send_html(404, 'Not Found', res, db); return } // just give a 404 to all evil countries

        // block individual known spammer ip addresses
        db.query('select count(*) as c from nukes where nuke_ip_address = ?', [state.ip], function (error, results, fields) {

            if (error)        { db.release(); throw error }
            if (results[0].c) { send_html(404, 'Not Found', res, db); return }

            collect_post_data(req, res, state, db)
        })
    })
}

function collect_post_data(req, res, state, db) { // if there is any POST data, accumulate it and append it to req object

    if (req.method == 'POST') {
        var body = ''

        req.on('data', function (data) {
            body += data

            if (body.length > 1e6) { // too much POST data, kill the connection
                req.connection.destroy()
                res.writeHead(413, {'Content-Type': 'text/plain'}).end()
            }
        })

        req.on('end', function () {
            var post_data   = qs.parse(body)
            Object.keys(post_data).map(function(key) { post_data[key] = post_data[key].trim() }) // trim all top level values, should all be strings
            state.post_data = post_data
            set_user(req, res, state, db)
        })
    }
    else {
        set_user(req, res, state, db)
    }
}

function set_user(req, res, state, db) { // update state with whether they are logged in or not

    // cookie is like whatdidyoubid=1_432d32044278053db427a93fc352235d where 1 is user and 432d... is md5'd password

    try {
        var user_id      = req.headers.cookie.split('=')[1].split('_')[0]
        var user_md5pass = req.headers.cookie.split('=')[1].split('_')[1]

        var query = db.query('select * from users where user_id = ? and user_md5pass = ?', [user_id, user_md5pass], function (error, results, fields) {

            if (error) { db.release(); throw error }

            if (0 == results.length) state.user = null
            else                     state.user = results[0]

            pages[state.page](req, res, state, db)
        })
    }
    catch(e) { // no valid cookie
        state.user = null
        pages[state.page](req, res, state, db)
    }
}

function login(req, res, state, db, email, password) {

    var query = db.query('select * from users where user_email = ? and user_md5pass = ?', [email, md5(password)],
             function (error, results, fields) {

        if (error) { db.release(); throw error }

        if (0 == results.length) {
            state.user         = null
            var user_id        = ''
            var user_md5pass   = ''
            state.login_failed = true
        }
        else {
            state.user       = results[0]
            var user_id      = state.user.user_id
            var user_md5pass = state.user.user_md5pass
        }

        html = pagefactory.render(state)

        var cookie = `whatdidyoubid=${user_id}_${user_md5pass}`
        var d      = new Date()
        var decade = new Date(d.getFullYear()+10, d.getMonth(), d.getDate()).toUTCString()

        var headers =  {
            'Content-Length' : html.length,
            'Content-Type'   : 'text/html',
            'Expires'        : d.toUTCString(),
            'Set-Cookie'     : `${cookie}; Expires=${decade}; Path=/`, // do NOT use "secure" or will not be able to test login in dev, w is http only
        }

        res.writeHead(200, headers)
        res.end(html)
        if (db) db.release()
    })
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

function message(message, state, res, db) {
    state.page    = 'message'
    state.message =  message
    send_html(200, pagefactory.render(state), res, db)
}

function send_html(code, html, res, db) {

    var headers =  {
        'Content-Type'   : 'text/html',
        'Content-Length' : html.length,
        'Expires'        : new Date().toUTCString()
    }

    res.writeHead(code, headers)
    res.end(html)
    if (db) db.release()
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

    var query = db.query('update users set user_key=? where user_email=?', [key, state.post_data.user_email],
        function (error, results, fields) {

            if (error) {
                message('Darn, something went wrong', state, res, db)
                return
            }

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
        })
}
