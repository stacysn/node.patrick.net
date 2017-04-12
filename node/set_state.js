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

                set_user(req, res, state, db)
            })
        })
    })
}

function set_user(req, res, state, db) { // update state with whether they are logged in or not

    // cookie is like whatdidyoubid=1_432d32044878053db427a93fc352235d where 1 is user and 432d... is md5'd password

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
    catch(e) { // req.headers.cookie dne, or some part of cookie was badly formed
        console.log(e)
        state.user = null
        pages[state.page](req, res, state, db)
    }
}

pages.home = function (req, res, state, db) {

    state.message = 'Hello World'

    db.query('select 18 as solution', function (error, results, fields) {
        state.body = state.body + results[0].solution
        send_html(200, pagefactory.render(state), res, db);
    })
}

pages.address = function (req, res, state, db) {

    state.message = 'An address page'

    db.query('select 18 as solution', function (error, results, fields) {
        state.body = state.body + results[0].solution
        send_html(200, pagefactory.render(state), res, db);
    })
}

pages.login = function (req, res, state, db) {

    // need to get these two from a login form
    var user_id      = 1
    var user_md5pass = 'd4fae4b45e689707e7dea506afc8c0e7'

    var cookie       = `whatdidyoubid=${user_id}_${user_md5pass}`
    var d            = new Date();
    var decade       = new Date(d.getFullYear()+10, d.getMonth(), d.getDate()).toUTCString()

    db.query('select * from users where user_id = ? and user_md5pass = ?', [user_id, user_md5pass], function (error, results, fields) {

        if (error) { db.release(); throw error }

        if (0 == results.length) state.user = null
        else                     state.user = results[0]

        html = pagefactory.render(state);

        var headers =  {
            'Content-Length' : html.length,
            'Content-Type'   : 'text/html',
            'Expires'        : new Date().toUTCString(),
            'Set-Cookie'     : `${cookie}; Expires=${decade}; Path=/; secure`,
        }

        res.writeHead(200, headers)
        res.end(html)
        if (db) db.release()
    })
}

pages.logout = function (req, res, state, db) {
    var cookie       = `whatdidyoubid=_`
    var d            = new Date();
    var decade       = new Date(d.getFullYear()+10, d.getMonth(), d.getDate()).toUTCString()

    state.user = null
    html = pagefactory.render(state);

    var headers =  {
        'Content-Length' : html.length,
        'Content-Type'   : 'text/html',
        'Expires'        : new Date().toUTCString(),
        'Set-Cookie'     : `${cookie}; Expires=${decade}; Path=/; secure`,
    }

    res.writeHead(200, headers)
    res.end(html)
    if (db) db.release()
}

function redirect(redirect_to, res, db) {

    var message = `Redirecting to ${ redirect_to }`

    var headers =  {
        'Set-Cookie'     : `${cookie}; Expires=${decade}; Path=/; secure`,
        'Location'       : redirect_to,
        'Content-Length' : message.length,
        'Expires'        : new Date().toUTCString()
    }

    res.writeHead(303, headers)
    res.end(message)
    if (db) db.release()
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
