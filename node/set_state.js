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

    if (!req.headers.cookie) {
        state.user = null
        pages[state.page](req, res, state, db)
    }
    else {
        console.log(req.headers.cookie)
        pages[state.page](req, res, state, db)
        /*
        $login = $db->get_row("select * from users where user_id = $user_id");

        $login = get_userrow($user_ID);

        if (!$login) {
            p_clearcookie();
            die("No such user_ID in users table: $user_ID");
        }

        if ( $login->user_pass == $md5_pass ) // Note that users.user_pass is stored md5'd.
            return true;
        else
            return false;
        */
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

function send_html(code, html, res, db) {
    var user_id      = 1
    var user_md5pass = '432d32044878053db427a93fc352235d'
    var cookie       = `whatdidyoubid=${user_id}_${user_md5pass}`
    var d            = new Date();
    var decade       = new Date(d.getFullYear()+10, d.getMonth(), d.getDate()).toUTCString()

    var headers =  {
        'Set-Cookie'     : `${cookie}; Expires=${decade}`,
        'Content-Type'   : 'text/html',
        'Content-Length' : html.length,
        'Expires'        : d.toUTCString()
    }

    res.writeHead(code, headers)
    res.end(html)
    if (db) db.release()
}
