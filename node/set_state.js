// set_state.js does all setting of state object

//console.log(req.headers.cookie, req.method)

exports.home = function (req, res, page, db) {

    var state = {}
    state.message = 'Hello World'

    //db.query('select 22 + 77 as solution where name=?', ['Patrick'], first_query)
    db.query('select 22 + 77 as solution', first_query)

    function first_query(error, results, fields) {

        state.body = results[0].solution

        db.query('select 18 as solution', second_query)
    }

    function second_query(error, results, fields) {

        state.body = state.body + results[0].solution

        html = pagefactory.render(state, page)

        send_response(html, res, db);
    }
}

exports.address = function (req, res, page, db) {

    var state = {}
    state.message = 'Hello World'

    //db.query('select 22 + 77 as solution where name=?', ['Patrick'], first_query)
    db.query('select 22 + 77 as solution', first_query)

    function first_query(error, results, fields) {

        state.body = results[0].solution

        db.query('select 18 as solution', second_query)
    }

    function second_query(error, results, fields) {

        state.body = state.body + results[0].solution

        html = pagefactory.render(state, page)

        send_response(html, res, db);
    }
}

function send_response(html, res, db) {
    res.writeHead(200, {
        'Content-Type'   : 'text/html',
        'Content-Length' : html.length,
        'Expires'        : new Date().toUTCString()
    })
    res.end(html)

    db.release()
}
