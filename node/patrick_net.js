try { conf = require('./conf.json') } catch(e) { console.log(e.message); process.exit(1) } // conf.json is required

cluster     = require('cluster')
http        = require('http')
moment      = require('moment-timezone') // via npm
mysql       = require('mysql')           // via npm
nodemailer  = require('nodemailer')      // via npm
os          = require('os')
querystring = require('querystring')
url         = require('url')

var locks = {} // allow only one connection from db pool per ip post

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

async function run(req, res) {

    var state = { // start accumulation of state for this request
        page    : url.parse(req.url).pathname.split('/')[1] || 'home',
        queries : [],
        req     : req,
        res     : res,
    }

    if (typeof pages[state.page] !== 'function') return send_html(404, `No page like "${req.url}"`, state)

    try {
        await connect_to_db(state)
        await block_countries(state)
        await block_nuked(state)
        await collect_post_data(state)
        await set_user(state)
        await pages[state.page](state)
    }
    catch(e) { send_html(e.code, e.message, state) }
}

var pages = {

    home : async function (state) {

        results = await query('select sql_calc_found_rows * from posts where post_modified > date_sub(now(), interval 7 day) and post_approved=1 order by post_modified desc limit 0, 20', null, state)
        state.message   = 'Free form forum'
        state.posts = results
        send_html(200, render(state), state)
    },
        
    users : async function (state) {

        try {
            var user_name = url.parse(state.req.url).path.split('/')[2].replace(/\W/g,'') // like /users/Patrick
            var sql       = 'select * from users where user_name=?'
            var sql_parms = [user_name]
        }
        catch(e) {
            var sql       = 'select * from users limit 20' // no username given, so show them all
            var sql_parms = null
        }

        state.users = await query(sql, sql_parms, state)
        send_html(200, render(state), state)
    },

    about : async function (state) {
        state.message = `About ${ conf.domain }`

        state.text = `${ conf.domain } is the bomb!`

        send_html(200, render(state), state)
    },

    postform : async function (state) { send_html(200, render(state), state) },

    post : async function (state) { // show a single post

        // get post's db row number from url, eg 47 from /post/47/slug-goes-here
        var post_id = url.parse(state.req.url).path.split('/')[2].replace(/\D/g,'')

        var results = await query('select * from posts where post_id=?', [post_id], state)

        if (0 == results.length) send_html(404, `No post with id "${post_id}"`, state)
        else {
            state.post = results[0]

            // now pick up the comment list for this post
            var results = await query('select * from comments left join users on comment_author=user_id where comment_post_id = ? order by comment_date',
                [post_id], state)

            if (results.length) state.comments = results
            send_html(200, render(state), state)
        }
    },

    key_login : async function (state) {

        key      = url.parse(state.req.url, true).query.key
        password = md5(Date.now() + conf.nonce_secret).substring(0, 6)

        // unfortunately a copy of home page sql
        state.posts         = await query('select * from posts order by post_modified desc limit 20', null, state)
        state.alert_content = `Your password is ${ password } and you are now logged in`
        state.message       = 'Increasing fair play for buyers and sellers'
        state.page          = 'home' // key_login generates home page html

        var results = await query('select user_email from users where user_activation_key = ?', [key], state)

        if (results.length) email = results[0].user_email
        else {
            message(`Darn, that key has already been used. Please try 'forgot password' if you need to log in.</a>`, state, state.res, state.db)
            return
        }

        // erase key so it cannot be used again, and set new password
        await query('update users set user_activation_key=null, user_pass=? where user_activation_key=?', [md5(password), key], state)

        login(state.req, state.res, state, state.db, email, password)
    },

    post_login : async function (state) {
        email    = state.post_data.email
        password = state.post_data.password

        login(state.req, state.res, state, state.db, email, password)
    },

    logout : async function (state) {

        state.user = null
        var d      = new Date()
        var html   = render(state)

        // you must use the undocumented "array" feature of writeHead to set multiple cookies, because json
		var headers = [
			['Content-Length' , html.length                               ],
			['Content-Type'   , 'text/html'                               ],
			['Expires'        , d.toUTCString()                           ],
			['Set-Cookie'     , `${ conf.usercookie }=_; Expires=${d}; Path=/`],
			['Set-Cookie'     , `${ conf.pwcookie   }=_; Expires=${d}; Path=/`]
		] // do not use 'secure' parm with cookie or will be unable to test login in dev, bc dev is http only

        state.res.writeHead(200, headers)
        state.res.end(html)
        if (state.db) state.db.release()
    },

    registration : async function (state) {

        Object.keys(state.post_data).map(key => { state.post_data[key] = strip_tags(state.post_data[key]) })

        if (/\W/.test(state.post_data.user_name)) return message('Please go back and enter username consisting only of letters', state, state.res, state.db);
        if (!/^\w.*@.+\.\w+$/.test(state.post_data.user_email)) return message('Please go back and enter a valid email',  state)

        var results = await query('select * from users where user_email = ?', [state.post_data.user_email], state)

        if (results[0]) {
            message(`That email is already registered. Please use the "forgot password" link above.</a>`, state)
            return
        }
        else {
            var results = await query('select * from users where user_name = ?', [state.post_data.user_name], state)

            if (results[0]) return message(`That user name is already registered. Please choose a different one.</a>`, state)
            else {
                await query('insert into users set ?', state.post_data, state)
                send_login_link(state.req, state.res, state, state.db)
            }
        }
    },

    recoveryemail : async function (state) {

        Object.keys(state.post_data).map(key => { state.post_data[key] = strip_tags(state.post_data[key]) })

        if (!/^\w.*@.+\.\w+$/.test(state.post_data.user_email)) { message('Please go back and enter a valid email post',  state); return }

        send_login_link(state.req, state.res, state, state.db)
    },

    new_post : async function (state) {

        post_data = state.post_data
        Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

        var results = await query('insert into posts set ?', post_data, state)
        redirect(`/post/${results.insertId}`, state.res, state.db)
    },

    new_comment : async function (state) {

        post_data = state.post_data
        Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

        if (!post_data.comment_content) { send_html(200, '', state); return } // empty comment

        // rate limit by user's ip address
        var results = await query('select (unix_timestamp(now()) - unix_timestamp(user_last_comment_time)) as ago from users where user_last_comment_time is not null and user_last_comment_ip = ? order by user_last_comment_time desc limit 1',
            [state.ip], state)

        if (results.length && results[0].ago < 2) { // this ip already commented less than two seconds ago
            state.page          = 'alert'
            state.alert_content = 'You are posting comments too quickly! Please slow down.'
            send_html(200, render(state), state)
        }
        else {

            post_data.comment_author   = state.user ? state.user.user_id : 0
            post_data.comment_content  = post_data.comment_content.linkify() // linkify, imagify, etc
            post_data.comment_dislikes = 0
            post_data.comment_likes    = 0
            post_data.comment_approved = 1
            post_data.comment_date     = new Date().toISOString().slice(0, 19).replace('T', ' ') // mysql datetime format

            await query('update users set user_last_comment_ip = ? where user_id = ?', [state.ip, state.user.user_id], state)

            var results = await query('insert into comments set ?', post_data, state)

            // now select the inserted row so that we pick up the comment_date time and user data for displaying the comment
            var results = await query('select * from comments left join users on comment_author=user_id where comment_id = ?', [results.insertId], state)

            if (results.length) state.comment = results[0]
            send_html(200, render(state), state)
        }
    },

    delete : async function (state) { // delete a comment

        var comment_id = url.parse(state.req.url).path.split('/')[2].replace(/\D/g,'') // get comment db row number from url, eg 47 from /delete/47

        // check that current user has permission to delete this comment

        if (!state.user) send_html(200, render(state), state) // do nothing if not logged in

        // delete comment only if current user is comment_author
        await query('delete from comments where comment_id = ? and comment_author = ?', [comment_id, state.user.user_id], state)

        send_html(200, render(state), state)
    },

} /////////////////////////////////////// end of pages{} definition ///////////////////////////////////////

function connect_to_db(state) {

    return new Promise(function(fulfill, reject) {

		pool.getConnection(function(err, db) {

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

async function block_countries(state) { // block entire countries like Russia because all comments from there are inevitably spam

    var results = await query('select country_evil from countries where inet_aton(?) >= country_start and inet_aton(?) <= country_end',
                                [state.ip, state.ip], state)

    if (results.length && results[0].country_evil) throw { code : 404, message : 'Not Found', }
}

async function block_nuked(state) { // block nuked users, usually spammers

    var results = await query('select count(*) as c from nukes where nuke_ip = ?', [state.ip], state)

    if (results[0].c) throw { code : 404, message : 'Not Found', }
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

async function set_user(state) { // update state with whether they are logged in or not

    try {
        var pairs = []

        state.req.headers.cookie.replace(/\s/g,'').split(';').forEach(function(element) {
            var name  = element.split('=')[0]
            var value = element.split('=')[1]

            pairs[name] = value
        })

        var results = await query('select * from users where user_id = ? and user_pass = ?', [pairs[conf.usercookie], pairs[conf.pwcookie]], state)

        if (0 == results.length) state.user = null
        else                     state.user = results[0]
    }
    catch(e) { // no valid cookie
        state.user = null
    }
}

async function login(req, res, state, db, email, password) {

    var results = await query('select * from users where user_email = ? and user_pass = ?', [email, md5(password)], state)

    if (0 == results.length) {
        state.login_failed_email = email
        state.user               = null
        var user_id              = ''
        var user_pass            = ''
    }
    else {
        state.login_failed_email = null
        state.user               = results[0]
        var user_id              = state.user.user_id
        var user_pass            = state.user.user_pass
    }

    html = render(state)

    var usercookie = `${ conf.usercookie }=${ user_id   }`
    var pwcookie   = `${ conf.pwcookie   }=${ user_pass }`
    var d		   = new Date()
    var decade	   = new Date(d.getFullYear()+10, d.getMonth(), d.getDate()).toUTCString()

    // you must use the undocumented "array" feature of writeHead to set multiple cookies, because json
    var headers = [
        ['Content-Length' , html.length                               ],
        ['Content-Type'   , 'text/html'                               ],
        ['Expires'        , d.toUTCString()                           ],
        ['Set-Cookie'     , `${usercookie}; Expires=${decade}; Path=/`],
        ['Set-Cookie'     , `${pwcookie};   Expires=${decade}; Path=/`]
    ] // do not use 'secure' parm with cookie or will be unable to test login in dev, bc dev is http only

    res.writeHead(200, headers)
    res.end(html)
        if (db) db.release()
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
        host:   conf.email.host,
        port:   conf.email.port,
        secure: false, // do not use TLS
        auth: {
            user: conf.email.user,
            pass: conf.email.password
        },
        tls: {
            rejectUnauthorized: false // do not fail on invalid certs
        }
    })
}

async function send_login_link(req, res, state, db) {

    baseurl  = (/localdev/.test(os.hostname())) ? conf.baseurl_dev : conf.baseurl // conf.baseurl_dev is for testing email
    key      = md5(Date.now() + conf.nonce_secret)
    key_link = `${ baseurl }/key_login?key=${ key }`

    var results = await query('update users set user_activation_key=? where user_email=?', [key, state.post_data.user_email], state)

    if (results.changedRows) {

        message('Please check your email for the login link', state, res, db)

        let mailOptions = {
            from:    conf.admin_email,
            to:      state.post_data.user_email,
            subject: `Your ${ conf.domain } login info`,
            html:    `Click here to log in and get your password: <a href='${ key_link }'>${ key_link }</a>`
        }

        get_transporter().sendMail(mailOptions, (error, info) => {
            if (error) { db.release(); throw error }
            console.log('Message %s sent: %s', info.messageId, info.response);
        })
    }
    else message(`Could not find user with email ${ state.post_data.user_email }`, state, res, db)
}

String.prototype.linkify = function(ref) {

    var urlPattern = /\b(?:https?|ftp):\/\/[a-z0-9-+&@#\/%?=~_|!:,.;]*[a-z0-9-+&@#\/%=~_|]/gim; // http://, https://, ftp://
    var pseudoUrlPattern = /(^|[^\/])(www\.[\S]+(\b|$))/gim;                                    // www. sans http:// or https://
    var imagePattern = />((?:https?):\/\/[a-z0-9-+&@#\/%?=~_|!:,.;]*[a-z0-9-+&@#\/%=~_|]\.(jpg|jpeg|gif|gifv|png|bmp))</gim;
    var emailpostPattern = /[\w.]+@[a-zA-Z_-]+?(?:\.[a-zA-Z]{2,6})+/gim;

    return this
        .replace(urlPattern,          '<a href="$&">$&</a>')
        .replace(pseudoUrlPattern,    '$1<a href="http://$2">$2</a>')
        .replace(imagePattern,        '><img src="$1"><') // it's already a link because of urlPattern above
        .replace(emailpostPattern, '<a href="mailto:$&">$&</a>')
}

function query(sql, sql_parms, state) {

    return new Promise(function(fulfill, reject) {
        var query

        var get_results = function (error, results, fields, timing) { // callback to give to state.db.query()

            //console.log(query.sql)

            if (error) { state.db.release(); reject(error) }

            state.queries.push({
                sql : query.sql,
                ms  : timing
            })

            fulfill(results)
        }

        query = sql_parms ? state.db.query(sql, sql_parms, get_results)
                          : state.db.query(sql,            get_results)
    })
}

Array.prototype.sortByProp = function(p){
    return this.sort(function(a,b){
        return (a[p] > b[p]) ? 1 : (a[p] < b[p]) ? -1 : 0
    })
}

function render(state) { // The render function never does IO. It simply assembles a page from state. It does not change state.

    var pages = {

        home : () => {
            return html(
                header(),
                alert(),
                midpage(
                    h1(),
                    post_list(),
                    new_post_button()
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

        postform : () => {
            return html(
                header(),
                midpage(
                    postform()
                ),
                footer()
            )
        },

        post : () => {
            return html(
                header(),
                midpage(
                    post(),
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
        new_comment : () => { return  comment(state.comment) },
    }

    //////////////////////////////////////// end of pages; all html is below ////////////////////////////////////////

    function html(...args) {

        var queries = state.queries.sortByProp('ms').map( (item) => { return `${ item.ms }ms ${ item.sql }` }).join('\n')

        return `<!DOCTYPE html><html lang="en">
            <head>
            <link href='/${ conf.stylesheet }' rel='stylesheet' type='text/css' />
            <link rel='icon' href='/favicon.ico' />
            <meta charset='utf-8' />
            <meta name='description' content='${ conf.description }' />
            <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no' />
            <title>${ conf.domain }</title>
            </head>
            <body>
                <div class="container" >
                ${ args.join('') }
                </div>
            </body>
            <script async src="/jquery.min.js"></script><!-- ${'\n' + queries + '\n'} -->
            </html>`
    }

    function header() {
        return `<div class='comment' >
            <a href='/' ><font color='ba114c'><h1 class="sitename" title='back to home page' >${ conf.domain }</h1></font></a> &nbsp;
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
                <a href='/users/${state.user.user_name}' >${img} ${state.user.user_name}</a>
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
                <div class='form-group'><input type='text' name='user_name' placeholder='choose username' class='form-control' id='user_name' ></div>
                <div class='form-group'><input type='text' name='user_email'      placeholder='email post'   class='form-control'                      ></div>
            </div>
            <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
            </form>
            <script type="text/javascript">document.getElementById('user_name').focus();</script>
        </div>`
    }

    function lostpwform() {
        var show = state.login_failed_email ? `value='${ state.login_failed_email }'` : `placeholder='email post'`

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

    function postform() {
        return `
        <h1>add new post</h1>
        <form action='/new_post' method='post' >
            <div class='form-group'><input name='post_num_street' type='text' class='form-control' placeholder='number and street only, like 123 Shady Lane' 
                    id='post_num_street' ></div>
            <div class='form-group'> <input name='post_apt' type='text' class='form-control' placeholder='apartment number, if any' > </div>
            <div class='form-group'> <input name='post_zip' type='text' class='form-control' placeholder='5 digit zip code' maxlength='5' > </div>
            <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
        </form>
        <script type="text/javascript">document.getElementById('post_num_street').focus();</script>`
    }

    function commentbox() {
        return `
        <div  id='newcomment' ></div>
        <form id='commentform' >
            <textarea            name='comment_content'    class='form-control' rows='10' placeholder='write a comment...' ></textarea><p>
            <input type='hidden' name='comment_post_id' value='${ state.post.post_id }' />
            <button class='btn btn-success btn-sm'
                onclick="$.post('/new_comment', $('#commentform').serialize()).done(function(data) {
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
        var u = c.user_name ? `<a href='/users/${c.user_name}'>${c.user_name}</a>` : 'anonymous'

        if (state.user) {
            var del = state.user.user_id == c.comment_author ?
                `<a href='#' onclick="$.get('/delete/${ c.comment_id }', function() { $('#${ c.comment_id }').remove() });return false">delete</a>` : ''
        }

        return `<div class="comment" id="${ c.comment_id }" >${ u } ${ format_date(c.comment_date) } ${ del }<br>${ c.comment_content }</div>`
    }

    function midpage(...args) { // just an id so we can easily swap out the middle of the page
        return `<div id="midpage" >
            ${ args.join('') }
            </div>`
    }

    function post_list() {

        if (state.posts) {
            var formatted = state.posts.map( (item) => {
                var link = post_link(item)
                return `<div class="post" >${ link }</div>`
            })
        }
        else formatted = []

        return formatted.join('')
    }

    function post() {
        var link = post_link(state.post)
        return `<h1>${ link }</h1>`
    }

    function post_link(post) {
        slug = slugify(`${post.post_title}`)
        return `<a href="/post/${post.post_id}/${slug}">${post.post_title}</a>`
    }

    function user_list() {

        if (state.users && state.users.length) {
            if (1 == state.users.length) {
                return user_page(state.users[0])
            }
            else if (state.users.length > 1) {
                var formatted = state.users.map( (item) => {
                    return `<div class="user" ><a href='/users/${ item.user_name }'>${ item.user_name }</a></div>`
                })
            }
        }
        else formatted = []

        return formatted.join('')
    }

    function user_page(u) {
        var img = user_icon(u)
        return `<center><a href='/users/${ u.user_name }' >${ img }</a><h2>${ u.user_name }</h2></p>joined ${ u.user_registered }</center>`
    }

    function slugify(s) { // url-safe pretty chars only; not used for navigation, only for seo and humans
        return s.replace(/\W/g,'-').toLowerCase().replace(/-+/,'-').replace(/^-+|-+$/,'')
    }

    function new_post_button() {
        return '<a href="/postform" class="btn btn-success btn-sm" title="start writing about a new post" ><b>add new post</b></a>'
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
            <a href='mailto:${ conf.admin_email }' >contact</a> &nbsp;
            `
    }

    function alert() {
        return state.alert_content ? `<script type='text/javascript'> alert('${ state.alert_content }'); </script>` : ''
    }

    function format_date(gmt_date) { // create localized date string from gmt date out of mysql
        var utz = state.user ? state.user.user_timezone : 'America/Los_Angeles'
        return moment(Date.parse(gmt_date)).tz(utz).format('YYYY MMMM Do h:mma z')
    }

    return pages[state.page]()

} // end of render
