try { conf = require('./conf.json') } catch(e) { console.log(e.message); process.exit(1) } // conf.json is required

cluster     = require('cluster')
http        = require('http')
moment      = require('moment-timezone') // via npm
mysql       = require('mysql')           // via npm
nodemailer  = require('nodemailer')      // via npm
os          = require('os')
querystring = require('querystring')
url         = require('url')

var locks = {} // allow only one connection from db pool per ip address

pool = mysql.createPool(conf.db)
pool.on('release', db => { // scan locks and delete the lock object which has db.threadId and any that are older than 2 seconds
    Object.keys(locks).map(ip => {
        if (locks[ip].threadId == db.threadId || locks[ip].ts < (Date.now() - 2000)) delete locks[ip]
    })
})

if (cluster.isMaster) {
    for (var i = 0; i < require('os').cpus().length; i++) cluster.fork();

    cluster.on('exit', function(worker, code, signal) {
        console.log(`worker pid ${worker.process.pid} died with code ${code} from signal ${signal}, replacing that worker`)
        cluster.fork()
    })
} else http.createServer(run).listen(conf.http_port)

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
                send_html(200, render(state), state)
            }
        )
    },
        
    users : state => {

        try {
            var user_screenname = url.parse(state.req.url).path.split('/')[2].replace(/\W/g,'') // like /users/Patrick
            var sql       = 'select * from users where user_screenname=?'
            var sql_parms = [user_screenname]
        }
        catch(e) {
            var sql       = 'select * from users' // no username given, so show them all
            var sql_parms = null
        }

        query(sql, sql_parms, state,
            results => {
                state.users = results
                send_html(200, render(state), state)
            }
        )
    },

    about : state => {
        state.message = 'About whatdidyoubid.com'

        state.text = `Realtors routinely block or "lose" bids that do not give their own agency both sides of the commission. whatdidyoubid.com is a place
        where bidders can list what they bid for a house so that sellers and other bidders can get an idea of the degree to which this takes place.`

        send_html(200, render(state), state)
    },

    addressform : state => { send_html(200, render(state), state) },

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
                            send_html(200, render(state), state)
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
        var html   = render(state)

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
                    send_html(200, render(state), state)
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
                                    send_html(200, render(state), state)
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

        if (!state.user) send_html(200, render(state), state) // do nothing if not logged in

        // delete comment only if current user is comment_author
        query('delete from comments where comment_id = ? and comment_author = ?', [comment_id, state.user.user_id], state,
            results => {
                send_html(200, render(state), state)
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
                var post_data   = querystring.parse(body)
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

            html = render(state)

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
    send_html(200, render(state), state)
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

function query(sql, sql_parms, state, cb) {

    var q

    var get_results = function (error, results, fields, timing) {
        if (error) { state.db.release(); throw error }
        state.queries.push({
            sql : q.sql,
            ms  : timing
        })
        cb(results)
    }

    q = sql_parms ? state.db.query(sql, sql_parms, get_results)
                  : state.db.query(sql,            get_results)
}

function create_err_handler(state) { // closure to pass back a promise rejection handler which has state in context

    return function(err) { // the actual rejection handler
        send_html(err.code, err.message, state)
    }
}

Array.prototype.sortByProp = function(p){
    return this.sort(function(a,b){
        return (a[p] > b[p]) ? 1 : (a[p] < b[p]) ? -1 : 0
    })
}

// The render function never does IO. It simply assembles a page from state, which will be overwritten on each call to render()
// state does not change at all once render is called

function render(state) {

    var pages = {

        home : () => {
            return html(
                header(),
                alert(),
                midpage(
                    h1(),
                    address_list(),
                    new_address_button()
                ),
                footer()
            )
        },

        users : () => {
            return html(
                header(),
                midpage(
                    user_list()
                ),
                footer()
            )
        },

        about : () => {
            return pages.message()
        },

        message : () => {
            return html(
                header(),
                midpage(
                    h1(),
                    text()
                ),
                footer()
            )
        },

        addressform : () => {
            return html(
                header(),
                midpage(
                    addressform()
                ),
                footer()
            )
        },

        address : () => {
            return html(
                header(),
                midpage(
                    address(),
                    comment_list(),
                    commentbox()
                ),
                footer()
            )
        },

        alert       : () => { return  alert()                },
        delete      : () => { return  ''                     },
        logout      : () => { return  loginprompt()          },
        post_login  : () => { return  icon_or_loginprompt()  },
        postcomment : () => { return  comment(state.comment) },
    }

    //////////////////////////////////////// end of pages; all html is below ////////////////////////////////////////

    function html(...args) {

        if (state.user && 'admin' == state.user.user_level)
            var queries = state.queries.sortByProp('ms').map( (item) => { return `${ item.ms }ms ${ item.sql }` }).join('\n')
        else
            var queries = ''

        return `<!DOCTYPE html><html lang="en">
            <head>
            <link href='/css/style_20170309.css' rel='stylesheet' type='text/css' />
            <link rel='icon' href='/favicon.ico' />
            <meta charset='utf-8' />
            <meta name='description' content='real estate, offers, bids' />
            <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no' />
            <title>What Did You Bid?</title>
            </head>
            <body>
                <div class="container" >
                ${ args.join('') }
                </div>
            </body>
            <script async src="/js/jquery.min.js"></script><!-- ${'\n' + queries + '\n'} -->
            </html>`
    }

    function header() {
        return `<div class='headerbox' >
            <a href='/' ><font color='ba114c'><h3 title='back to home page' >What Did You Bid?</h3></font></a> &nbsp;
            <div style='float:right' >${ icon_or_loginprompt() }</div><p>
            </div>`
    }

    function icon_or_loginprompt() {
        if (state.user) return id_box()
        else            return loginprompt()
    }

    function user_icon(u) {
        return u.user_icon ? `<img src='${u.user_icon}' width='${u.user_icon_width}' height='${u.user_icon_height}' >` : ''
    }

    function id_box() {

        var img = user_icon(state.user)

        return `
            <div id='status' >
                <a href='/users/${state.user.user_screenname}' >${img} ${state.user.user_screenname}</a>
                <p>
                <a href='#' onclick="$.get('/logout', function(data) { $('#status').html(data) });return false">logout</a>
            </div>`
    }

    function loginprompt() {

        return `
            <div id='status' >
                ${ state.login_failed_email ? 'login failed' : '' }
                <form id='loginform' >
                    <fieldset>
                        <input id='email'    name='email'    placeholder='email'    type='text'     required >   
                        <input id='password' name='password' placeholder='password' type='password' required >
                    </fieldset>
                    <fieldset>
                        <input type='submit' id='submit' value='log in'
                            onclick="$.post('/post_login', $('#loginform').serialize()).done(function(data) { $('#status').html(data) });return false">

                        <a href='#' onclick="document.getElementById('midpage').innerHTML = lostpwform.innerHTML;  return false" >forgot password</a>
                        <a href='#' onclick="document.getElementById('midpage').innerHTML = registerform.innerHTML; return false" >register</a>
                    </fieldset>
                </form>
                <div style='display: none;' >
                    ${ lostpwform()   }
                    ${ registerform() }
                </div>
            </div>`
    }

    function tabs() {
        return `<ul class='nav nav-tabs'>
            <li class='active' > <a href='/?order=active'   title='most recent comments' >active</a></li>
            <li                > <a href='/?order=comments' title='most comments'        >comments</a></li>
            <li                > <a href='/?order=new'      title='newest'               >new</a></li>
            <li                > <a href='/?order=private'  title='your private chats'   >private</a></li>
            </ul>`
    }

    function registerform() {
        return `
        <div id='registerform' >
            <h1>register</h1>
            <form action='/registration' method='post'>
            <div >
                <div class='form-group'><input type='text' name='user_screenname' placeholder='choose username' class='form-control' id='user_screenname' ></div>
                <div class='form-group'><input type='text' name='user_email'      placeholder='email address'   class='form-control'                      ></div>
            </div>
            <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
            </form>
            <script type="text/javascript">document.getElementById('user_screenname').focus();</script>
        </div>`
    }

    function lostpwform() {
        var show = state.login_failed_email ? `value='${ state.login_failed_email }'` : `placeholder='email address'`

        return `
        <div id='lostpwform' >
            <h1>reset password</h1>
            <form action='/recoveryemail' method='post'>
                <div class='form-group'><input type='text' name='user_email' ${ show } class='form-control' id='lost_pw_email' ></div>
                <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
            </form>
            <script type="text/javascript">document.getElementById('lost_pw_email').focus();</script>
        </div>`
    }

    function addressform() {
        return `
        <h1>add new address</h1>
        <form action='/postaddress' method='post' >
            <div class='form-group'><input name='address_num_street' type='text' class='form-control' placeholder='number and street only, like 123 Shady Lane' 
                    id='address_num_street' ></div>
            <div class='form-group'> <input name='address_apt' type='text' class='form-control' placeholder='apartment number, if any' > </div>
            <div class='form-group'> <input name='address_zip' type='text' class='form-control' placeholder='5 digit zip code' maxlength='5' > </div>
            <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
        </form>
        <script type="text/javascript">document.getElementById('address_num_street').focus();</script>`
    }

    function commentbox() {
        return `
        <div  id='newcomment' ></div>
        <form id='commentform' >
            <textarea            name='comment_content'    class='form-control' rows='10' placeholder='write a comment...' ></textarea><p>
            <input type='hidden' name='comment_address_id' value='${ state.address.address_id }' />
            <button class='btn btn-success btn-sm'
                onclick="$.post('/postcomment', $('#commentform').serialize()).done(function(data) {
                    if (data) $('#newcomment').append(data)
                    document.getElementById('commentform').reset() // clear the textbox
                })
                return false" >submit</button>
        </form>`
    }

    function h1() {
        return `<h1>${ state.message }</h1>`
    }

    function text() {
        return `${ state.text || '' }`
    }

    function comment(c) {
        var u = c.user_screenname ? `<a href='/users/${c.user_screenname}'>${c.user_screenname}</a>` : 'anonymous'

        if (state.user) {
            var del = state.user.user_id == c.comment_author ?
                `<a href='#' onclick="$.get('/delete/${ c.comment_id }', function() { $('#${ c.comment_id }').remove() });return false">delete</a>` : ''
        }

        return `<div class="comment" id="${ c.comment_id }" >${ u } ${ format_date(c.comment_created) } ${ del }<br>${ c.comment_content }</div>`
    }

    function midpage(...args) { // just an id so we can easily swap out the middle of the page
        return `<div id="midpage" >
            ${ args.join('') }
            </div>`
    }

    function address_list() {

        if (state.addresses) {
            var formatted = state.addresses.map( (item) => {
                var link = address_link(item)
                return `<div class="address" >${ link }</div>`
            })
        }
        else formatted = []

        return formatted.join('')
    }

    function address() {
        var link = address_link(state.address)
        return `<h1>${ link }</h1>`
    }

    function address_link(addr) {
        slug = slugify(`${addr.address_num_street} ${addr.zip_city} ${addr.zip_state} ${addr.zip_code}`)
        return `<a href="/address/${addr.address_id}/${slug}">${addr.address_num_street}, ${addr.zip_city} ${addr.zip_state} ${addr.zip_code}</a>`
    }

    function user_list() {

        if (state.users && state.users.length) {
            if (1 == state.users.length) {
                return user_page(state.users[0])
            }
            else if (state.users.length > 1) {
                var formatted = state.users.map( (item) => {
                    return `<div class="user" ><a href='/users/${ item.user_screenname }'>${ item.user_screenname }</a></div>`
                })
            }
        }
        else formatted = []

        return formatted.join('')
    }

    function user_page(u) {
        var img = user_icon(u)
        return `<center><a href='/users/${ u.user_screenname }' >${ img }</a><h2>${ u.user_screenname }</h2></p>joined ${ u.user_registered }</center>`
    }

    function slugify(s) { // url-safe pretty chars only; not used for navigation, only for seo and humans
        return s.replace(/\W/g,'-').toLowerCase().replace(/-+/,'-').replace(/^-+|-+$/,'')
    }

    function new_address_button() {
        return '<a href="/addressform" class="btn btn-success btn-sm" title="start writing about a new address" ><b>add new address</b></a>'
    }

    function comment_list() {
        if (state.comments) {
            var formatted = state.comments.map( (item) => {
                return comment(item)
            })

            return formatted.join('')
        }
    }

    function footer() {
        return `
            <p>
            <center>
            <a href='/'>home</a> &nbsp;
            <a href='#'>top</a> &nbsp;
            <a href="/users">users</a> &nbsp;
            <a href="/about">about</a> &nbsp;
            <a href='mailto:p@whatdidyoubid.com'>suggestions</a> &nbsp;
            <a href='mailto:p@whatdidyoubid.com' >contact</a> &nbsp;
            <a href='https://github.com/killelea/whatdidyoubid.com' >source code</a> &nbsp;
            `
    }

    function alert() {
        return state.alert_content ? `<script type='text/javascript'> alert('${ state.alert_content }'); </script>` : ''
    }

    function format_date(utc) {
        var utz = state.user ? state.user.user_timezone : 'America/Los_Angeles'
        return moment(Date.parse(utc)).tz(utz).format('YYYY MMMM Do h:mma z')
    }

    return pages[state.page]()

} // end of render
