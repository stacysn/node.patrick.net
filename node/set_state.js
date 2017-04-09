// set_state.js does all setting of state object

exports.home = function (req, res, page) {

    pool.getConnection(function(err, connection) {

        console.log(req.headers.cookie, req.method)

        var state = {}
        state.message = 'Hello World'

        //connection.query('select 22 + 77 as solution where name=?', ['Patrick'], first_query)
        connection.query('select 22 + 77 as solution', first_query)

        function first_query(error, results, fields) {

            state.body = results[0].solution

            connection.query('select 18 as solution', second_query)
        }

        function second_query(error, results, fields) {

            state.body = state.body + results[0].solution

            html = pagefactory.render(state, page)

            res.writeHead(200, {
                'Content-Type'   : 'text/html',
                'Content-Length' : html.length,
                'Expires'        : new Date().toUTCString()
            })
            res.end(html)

            connection.release()
        }
    })
}
