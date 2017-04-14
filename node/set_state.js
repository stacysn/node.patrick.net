var pages = {}

exports.run = function (req, res, page) {

    // if there is no such page, exit immediately without using any db resources
    if (typeof pages[page] !== 'function') { send_html(404, `No page like "${req.url}"`, res, null); return }

    var state = {} // start accumulation of state
    state.page = page

    pool.getConnection(function(err, db) {
        if (err) throw err

        var ip = req.headers['x-forwarded-for'] // we get the client ip from nginx's forwarding it

        // block entire countries like Russia because all comments from there are inevitably spam
        db.query('select country_evil from countries where inet_aton(?) >= country_start and inet_aton(?) <= country_end', [ip, ip],
                 function (error, results, fields) {

            if (error)                   { db.release(); throw error }
            if (results[0].country_evil) { send_html(404, 'Not Found', res, db); return } // just give a 404 to all evil countries

            // block individual known spammer ip addresses
            db.query('select count(*) as c from nukes where nuke_ip_address = ?', [ip], function (error, results, fields) {

                if (error)        { db.release(); throw error }
                if (results[0].c) { send_html(404, 'Not Found', res, db); return }

                collect_post_data(req, res, state, db)
            })
        })
    })
}

pages.home = function (req, res, state, db) {

    var query = db.query('select * from addresses', function (error, results, fields) {
        if (error) { db.release(); throw error }

        if (0 == results.length) {
            send_html(404, 'no addresses found', res, null)
        }
        else {
            state.addresses = results
            state.message   = 'Increasing fair play for buyers and sellers'
            send_html(200, pagefactory.render(state), res, db)
        }
    })
}

pages.addressform = function (req, res, state, db) {
    state.message = 'Enter new address'
    send_html(200, pagefactory.render(state), res, db)
}

pages.address = function (req, res, state, db) {

    var address_id = url.parse(req.url).path.split('/')[2].replace(/\D/g,'') // get address' db row number from url, eg /address/47/slug-goes-here

    var query = db.query('select * from addresses where address_id = ?', [address_id], function (error, results, fields) {
        if (error) { db.release(); throw error }

        if (0 == results.length) {
            send_html(404, `No address with id "${address_id}"`, res, null)
        }
        else {
            state.address = results[0]

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

pages.login = function (req, res, state, db) {

    post_data = state.post_data
    delete state.post_data // so login info never accidentally appears in state output

    Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

    var query = db.query('select * from users where user_email = ? and user_md5pass = ?', [post_data.email, md5(post_data.password)],
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

        var cookie       = `whatdidyoubid=${user_id}_${user_md5pass}`
        var d            = new Date()
        var decade       = new Date(d.getFullYear()+10, d.getMonth(), d.getDate()).toUTCString()

        var headers =  {
            'Content-Length' : html.length,
            'Content-Type'   : 'text/html',
            'Expires'        : d.toUTCString(),
            'Set-Cookie'     : `${cookie}; Expires=${decade}; Path=/; secure`,
        }

        res.writeHead(200, headers)
        res.end(html)
        if (db) db.release()
    })
}

pages.logout = function (req, res, state, db) {
    var cookie       = `whatdidyoubid=_`
    var d            = new Date()
    var decade       = new Date(d.getFullYear()+10, d.getMonth(), d.getDate()).toUTCString()

    state.user = null
    html = pagefactory.render(state)

    var headers =  {
        'Content-Length' : html.length,
        'Content-Type'   : 'text/html',
        'Expires'        : d.toUTCString(),
        'Set-Cookie'     : `${cookie}; Expires=${decade}; Path=/; secure`,
    }

    res.writeHead(200, headers)
    res.end(html)
    if (db) db.release()
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
            redirect(`/address/${results.insertId}/slug`, res, db)
        })
}

pages.postcomment = function (req, res, state, db) {

    post_data = state.post_data
    Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

    if (post_data.comment_content) {
        post_data.comment_author_ip = req.headers['x-forwarded-for']

        // rate limit by ip address
        var query = db.query('select (now() - comment_created) as ago from comments where comment_author_ip = ? order by comment_created desc limit 1',
            [post_data.comment_author_ip],
            function (error, results, fields) {
                if (error) { db.release(); throw error }

                if (results.length && results[0].ago < 2) {
                    state.comment = post_data
                    state.comment.comment_content = 'You are posting comments too quickly! Please slow down.'
                    send_html(200, pagefactory.render(state), res, db)
                }
                else {
                    var query = db.query('insert into comments set ?', post_data, function (error, results, fields) {
                        if (error) { db.release(); throw error }

                        state.comment = post_data
                        send_html(200, pagefactory.render(state), res, db)
                    })
                }
            })
    }
    else { // empty comment, ignore
        state.comment = post_data
        send_html(200, pagefactory.render(state), res, db)
    }
}

//////////////////////////////////////// end of pages; helper functions below ////////////////////////////////////////

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
    state.message = message
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

function strip_tags(s) {
    return s.replace(/(<([^>]+)>)/g,'')
}

function set_user(req, res, state, db) { // update state with whether they are logged in or not

    // cookie is like whatdidyoubid=1_432d32044278053db427a93fc352235d where 1 is user and 432d... is md5'd password

    try {
        var user_id      = req.headers.cookie.split('=')[1].split('_')[0]
        var user_md5pass = req.headers.cookie.split('=')[1].split('_')[1]

        db.query('select * from users where user_id = ? and user_md5pass = ?', [user_id, user_md5pass], function (error, results, fields) {

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
