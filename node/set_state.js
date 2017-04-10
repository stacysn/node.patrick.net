//console.log(req.headers.cookie, req.method)

var pages = {}

exports.run = function (req, res, page) {

    // if there is no such page, exit immediately without using any db resources
    if (typeof pages[page] !== 'function') send_html(404, `No page like "${page}"`, res, null);

    pool.getConnection(function(err, db) {
        if (err) throw err

        db.query('select country_name, country_evil from countries where inet_aton(?) >= country_start and inet_aton(?) <= country_end',
                 [req.headers['x-forwarded-for'], req.headers['x-forwarded-for']], function (error, results, fields) {

            if (error) throw error

            if (results[0].country_evil) send_html(404, 'Not Found', res, db) // just give a 404 to all evil countries

            else (pages[page](req, res, page, db))
        })
    })
}

pages.home = function (req, res, page, db) {

    var state = {}
    state.page = page
    state.message = 'Hello World'

    db.query('select 18 as solution', function (error, results, fields) {
        state.body = state.body + results[0].solution

        send_html(200, pagefactory.render(state), res, db);
    })
}

function send_html(code, html, res, db) {
    res.writeHead(code, {
        'Content-Type'   : 'text/html',
        'Content-Length' : html.length,
        'Expires'        : new Date().toUTCString()
    })
    res.end(html)
    if (db) db.release()
}
