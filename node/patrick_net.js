// Copyright 2017 by Patrick Killelea under the ISC license

try { conf = require('./conf.json') } catch(e) { console.log(e.message); process.exit(1) } // conf.json is required

cluster     = require('cluster')
http        = require('http')
moment      = require('moment-timezone') // installed via npm
mysql       = require('mysql')           // installed via npm
nodemailer  = require('nodemailer')      // installed via npm
os          = require('os')
querystring = require('querystring')
url         = require('url')

var locks = {} // global locks to allow only one db connection per ip; helps mitigate dos attacks

pool = mysql.createPool(conf.db)
pool.on('release', db => { // delete the lock for the released db.threadId, and any locks that are older than 2 seconds
    Object.keys(locks).map(ip => {
        if (locks[ip].threadId == db.threadId || locks[ip].ts < (Date.now() - 2000)) delete locks[ip]
    })
})

if (cluster.isMaster) {
    for (var i = 0; i < require('os').cpus().length; i++) cluster.fork()

    cluster.on('exit', function(worker, code, signal) {
        console.log(`worker pid ${worker.process.pid} died with code ${code} from signal ${signal}, replacing that worker`)
        cluster.fork()
    })
} else http.createServer(run).listen(conf.http_port)

////////////////////////////////////////////////////////////////////////////////
// end of top-level code; everything else is in a function
////////////////////////////////////////////////////////////////////////////////

function run(req, res) { // handle a single http request

    var state = { // start accumulation of state for this request
        conf    : conf,
        page    : segments(req.url)[1] || 'home',
        queries : [],
        req     : req,
        res     : res,
    }

    render(state)
}

function get_connection_from_pool(state) {

    return new Promise(function(fulfill, reject) {

		pool.getConnection(function(err, db) {

            state.db = db
			state.ip = state.req.headers['x-forwarded-for']

			// query or set a database lock for this ip; each ip is allowed only one outstanding connection at a time
			if (locks[state.ip]) { send_html(403, 'Rate Limit Exceeded', state); console.log(`Rate limit exceeded by ${ state.ip }`); return }
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

    if (results.length && results[0].country_evil) throw { code : 403, message : 'permission denied' }
}

async function block_nuked(state) { // block nuked users, usually spammers

    var results = await query('select count(*) as c from nukes where nuke_ip = ?', [state.ip], state)

    if (results[0].c) throw { code : 403, message : 'permission denied' }
}

async function header_data(state) { // data that the page header needs to render
	return {
        comments : (await query(`select count(*) as c from comments`,                                      null, state))[0].c, // int
        onlines  :  await query(`select * from onlines order by online_username`,                          null, state),       // obj
        posts    : (await query(`select count(*) as c from posts`,                                         null, state))[0].c, // int
        top3     :  await query(`select post_topic, count(*) as c from posts
                                where length(post_topic) > 0 group by post_topic order by c desc limit 3`, null, state),       // obj
        tot      : (await query(`select count(*) as c from users`,                                         null, state))[0].c, // int
	}
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

		// update users currently online for display in header
        await query(`delete from onlines where online_last_view < date_sub(now(), interval 5 minute)`, null, state)
        await query(`insert into onlines (online_user_id, online_username, online_last_view) values (?, ?, now())
	                 on duplicate key update online_last_view=now()`, [state.user.user_id, state.user.user_name], state)

    }
    catch(e) { // no valid cookie
        state.user = null
    }
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
    render(state)
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

        message('Please check your email for the login link', state)

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
    else message(`Could not find user with email ${ state.post_data.user_email }`, state)
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

function segments(path) { // return url path split up as array of cleaned \w strings
    return url.parse(path).path.split('/').map(segment => segment.replace(/\W/g,''))
}

async function render(state) {

    var pages = {

        about : async function() {

            state.header_data = await header_data(state)

            let content = html(
                midpage(
					about_this_site()
                )
            )

            send_html(200, content, state)
        },

        delete : async function() { // delete a comment

            var comment_id = segments(state.req.url)[2]

            if (!state.user) send_html(200, content, state) // do nothing if not logged in

            // delete comment only if current user is comment_author
            await query('delete from comments where comment_id = ? and comment_author = ?', [comment_id, state.user.user_id], state)

            send_html(200, '', state)
        },

        home : async function () {

            state.header_data = await header_data(state)

            let sql = `select sql_calc_found_rows * from posts
                       where post_modified > date_sub(now(), interval 7 day) and post_approved=1
                       order by post_modified desc limit 0, 20`

            state.posts = await query(sql, null, state)

            let content = await html(
                midpage(
                    post_list()
                )
            )

            send_html(200, content, state)
        },

        key_login : async function() {

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
                message(`Darn, that key has already been used. Please try 'forgot password' if you need to log in.</a>`, state)
                return
            }

            // erase key so it cannot be used again, and set new password
            await query('update users set user_activation_key=null, user_pass=? where user_activation_key=?', [md5(password), key], state)

            login(state.req, state.res, state, state.db, email, password)
        },

        logout : async function() {

            state.user = null
            var d      = new Date()
            var html   = loginprompt(state)

            // you must use the undocumented "array" feature of res.writeHead to set multiple cookies, because json
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

        message : async function() {

            state.header_data = await header_data(state)

            let content = html(
                midpage(
                    h1(),
                    text()
                )
            )

            send_html(200, content, state)
        },

        new_comment : async function() {

            post_data = state.post_data
            Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

            if (!post_data.comment_content) { send_html(200, '', state); return } // empty comment

            // rate limit by user's ip address
            var results = await query('select (unix_timestamp(now()) - unix_timestamp(user_last_comment_time)) as ago from users where user_last_comment_time is not null and user_last_comment_ip = ? order by user_last_comment_time desc limit 1',
                [state.ip], state)

            if (results.length && results[0].ago < 2) { // this ip already commented less than two seconds ago
                send_html(200, alert('You are posting comments too quickly! Please slow down'), state)
            }
            else {

                post_data.comment_author   = state.user ? state.user.user_id : 0
                post_data.comment_content  = post_data.comment_content.linkify() // linkify, imagify, etc
                post_data.comment_dislikes = 0
                post_data.comment_likes    = 0
                post_data.comment_approved = 1
                post_data.comment_date     = new Date().toISOString().slice(0, 19).replace('T', ' ') // mysql datetime format

                await query('update users set user_last_comment_ip = ? where user_id = ?', [state.ip, state.user.user_id], state)
                await query('update posts set post_modified = ? where post_id = ?', [post_data.comment_date, post_data.comment_post_id], state)

                var results = await query('insert into comments set ?', post_data, state)

                // now select the inserted row so that we pick up the comment_date time and user data for displaying the comment
                var results = await query('select * from comments left join users on comment_author=user_id where comment_id = ?', [results.insertId], state)

                if (results.length) state.comment = results[0]

                send_html(200, comment(state.comment), state)
            }
        },

        new_post : async function() {

            post_data = state.post_data
            Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

            post_data.post_approved = 1 // create a function to check content before approving!

            var results = await query('insert into posts set ?, post_modified=now()', post_data, state)

            redirect(`/post/${results.insertId}`, state.res, state.db)
        },

        post : async function() { // show a single post

            // get post's db row number from url, eg 47 from /post/47/slug-goes-here
            var post_id = segments(state.req.url)[2]

            var results = await query('select * from posts where post_id=?', [post_id], state)

            if (0 == results.length) send_html(404, `No post with id "${post_id}"`, state)
            else {
                state.post = results[0]

                state.header_data = await header_data(state)

                // now pick up the comment list for this post
                var results = await query('select * from comments left join users on comment_author=user_id where comment_post_id = ? order by comment_date',
                    [post_id], state)

                if (results.length) state.comments = results

                let content = html(
                    midpage(
                        post(),
                        comment_list(),
                        commentbox()
                    )
                )

                send_html(200, content, state)
            }
        },

        post_login : async function() {
            email    = state.post_data.email
            password = state.post_data.password

            login(state.req, state.res, state, state.db, email, password)
        },

        postform : async function() {

            state.top3 = await top3(state)
            state.header_data = await header_data(state)

            let content = html(
                midpage(
                    postform()
                )
            )

            send_html(200, content, state)
        },

        recoveryemail : async function() {

            Object.keys(state.post_data).map(key => { state.post_data[key] = strip_tags(state.post_data[key]) })

            if (!/^\w.*@.+\.\w+$/.test(state.post_data.user_email)) return message('Please go back and enter a valid email',  state)

            send_login_link(state.req, state.res, state, state.db)
        },

        registration : async function() {

            Object.keys(state.post_data).map(key => { state.post_data[key] = strip_tags(state.post_data[key]) })

            if (/\W/.test(state.post_data.user_name)) return message('Please go back and enter username consisting only of letters', state);
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

        topic : async function() {

            var topic = segments(state.req.url)[2] // like /topics/housing

            let sql = 'select sql_calc_found_rows * from posts where post_topic = ? and post_approved=1 order by post_modified desc limit 0, 20'

            state.posts = await query(sql, [topic], state)
            state.message = '#' + topic
        
            state.header_data = await header_data(state)

            let content = html(
                midpage(
                    h1(),
                    post_list()
                )
            )

            send_html(200, content, state)
        },

        topics : async function () {

            let sql = 'select post_topic, count(*) as c from posts where length(post_topic) > 0 group by post_topic having c >=3 order by c desc'

            state.topics = await query(sql, null, state)

            state.message = 'Topics'
        
            state.header_data = await header_data(state)

            let content = html(
                midpage(
                    h1(),
                    topic_list()
                )
            )

            send_html(200, content, state)
        },

        user : async function() {

            var user_name = segments(state.req.url)[2] // like /user/Patrick
            var sql       = 'select * from users where user_name=?'
            var sql_parms = [user_name]

            state.users       = await query(sql, sql_parms, state)
            state.header_data = await header_data(state)

            let content = html(
                midpage(
                    user_info()
                )
            )

            send_html(200, content, state)
        },

        users : async function() {

            state.header_data = await header_data(state)

            var sql       = 'select * from users limit 20'
            var sql_parms = null
            state.users = await query(sql, sql_parms, state)

            let content = html(
                midpage(
                    user_list()
                )
            )

            send_html(200, content, state)
        },

    } // end of pages /////////////////////////////////////////////////////////

    function about_this_site() {
        return `<h1>About ${ conf.domain }</h1>${ conf.domain } is the bomb!`
    }


    function alert(message) {
        return `<script type='text/javascript'> alert('${ message }'); </script>`
    }

    function brag() {

        var online_list = state.header_data.onlines.map(u => `<a href='/user/${u.online_username}'>${u.online_username}</a>`).join(', ')

        return `${ state.header_data.comments.toLocaleString('en') } comments in
                ${ state.header_data.posts.toLocaleString('en') } posts by
                <a href='/users'>${ state.header_data.tot.toLocaleString('en') } registered users</a>,
                ${ state.header_data.onlines.length } online now: ${ online_list }`
    }

    function comment(c) {
        var u = c.user_name ? `<a href='/user/${c.user_name}'>${c.user_name}</a>` : 'anonymous'

        if (state.user) {
            var del = state.user.user_id == c.comment_author ?
                `<a href='#' onclick="$.get('/delete/${ c.comment_id }', function() { $('#${ c.comment_id }').remove() });return false">delete</a>` : ''
        }

        return `<div class="comment" id="${ c.comment_id }" >${ u } ${ format_date(c.comment_date) } ${ del }<br>${ c.comment_content }</div>`
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

    function comment_list() {
        if (state.comments) {
            var formatted = state.comments.map( (item) => {
                return comment(item)
            })

            return formatted.join('')
        }
    }

    function format_date(gmt_date) { // create localized date string from gmt date out of mysql
        var utz = state.user ? state.user.user_timezone : 'America/Los_Angeles'
        return moment(Date.parse(gmt_date)).tz(utz).format('YYYY MMMM Do h:mma z')
    }

    function header() {

        return `<div class='comment' >
            <div style='float:right' >${ icon_or_loginprompt(state) }</div>
            <a href='/' ><h1 class='sitename' title='back to home page' >${ conf.domain }</h1></a><br>
            ${ top_topics() + '<br>' + brag() + '<br>' + new_post_button() }
            </div>`
    }

    function h1() {
        return `<h1>${ state.message }</h1>`
    }

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
                ${ header() }
                ${ args.join('') }
                ${ footer() }
                </div>
            </body>
            <script async src="/jquery.min.js"></script><!-- ${'\n' + queries + '\n'} -->
            </html>`
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

        html = icon_or_loginprompt(state)

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

    function midpage(...args) { // just an id so we can easily swap out the middle of the page
        return `<div id="midpage" >
            ${ args.join('') }
            </div>`
    }

    function new_post_button() {
        return '<a href="/postform" class="btn btn-success btn-sm" title="start writing about a new post" ><b>new post</b></a>'
    }

    function post_link(post) {
        slug = slugify(`${post.post_title}`)
        return `<a href="/post/${post.post_id}/${slug}">${post.post_title}</a>`
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

        return `<div class='comment' ><h1>${ link }</h1>${ state.post.post_content }</div>`
    }

    function postform() { // need to add conditional display of user-name chooser for non-logged in users
        return `
        <h1>new post</h1>
        <form action='/new_post' method='post' >
            <div class='form-group'><input name='post_title' type='text' class='form-control' placeholder='title' id='title' ></div>
            <textarea class='form-control' name='post_content' rows='12' id='content' placeholder='write something...' ></textarea><p>
            <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
        </form>
        <script type="text/javascript">document.getElementById('title').focus();</script>`
    }

    function slugify(s) { // url-safe pretty chars only; not used for navigation, only for seo and humans
        return s.replace(/\W/g,'-').toLowerCase().replace(/-+/,'-').replace(/^-+|-+$/,'')
    }

    function text() {
        return `${ state.text || '' }`
    }

    function user_list() {

        var formatted = state.users.map( (item) => {
            return `<div class="user" ><a href='/user/${ item.user_name }'>${ item.user_name }</a></div>`
        })

        return formatted.join('')
    }

    function user_icon(u) {
        return u.user_icon ? `<img src='${u.user_icon}' width='${u.user_icon_width}' height='${u.user_icon_height}' >` : ''
    }

    function user_info() {

        if (state.users && state.users.length) {
            let u = state.users[0]

            var img = user_icon(u)
            return `<center><a href='/user/${ u.user_name }' >${ img }</a><h2>${ u.user_name }</h2></p>joined ${ u.user_registered }</center>`
        }
        else formatted = []

        return formatted.join('')
    }

    function icon_or_loginprompt() {
        if (state.user) return id_box(state)
        else            return loginprompt(state)
    }

    function id_box() {

        var img = user_icon(state.user)

        return `
            <div id='status' >
                <a href='/user/${state.user.user_name}' >${img} ${state.user.user_name}</a>
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
                        <a href='#' onclick="midpage.innerHTML = lostpwform.innerHTML;  return false" >forgot password</a>
                        <a href='#' onclick="midpage.innerHTML = registerform.innerHTML; return false" >register</a>
                    </fieldset>
                </form>
                <div style='display: none;' >
                    ${ lostpwform(state)   }
                    ${ registerform() }
                </div>
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

    function footer() {
        return `
            <p>
            <center>
            <a href='/'>home</a> &nbsp;
            <a href='#'>top</a> &nbsp;
            <a href="/topics">topics</a> &nbsp;
            <a href="/users">users</a> &nbsp;
            <a href="/about">about</a> &nbsp;
            <a href='mailto:${ state.conf.admin_email }' >contact</a> &nbsp;
            `
    }

    function tabs() {
        return `<ul class='nav nav-tabs'>
            <li class='active' > <a href='/?order=active'   title='most recent comments'       >active</a></li>
            <li                > <a href='/?order=comments' title='most comments in last week' >comments</a></li>
            <li                > <a href='/?order=likes'    title='most likes in last week'    >private</a></li>
            <li                > <a href='/?order=new'      title='newest'                     >new</a></li>
            </ul>`
    }


    function topic_list() {
        if (state.topics) {
            var formatted = state.topics.map( (item) => {
                return `<a href='/topic/${ item.post_topic }'>#${ item.post_topic }</a>`
            })

            return formatted.join(' ')
        }
    }

    function top_topics() {
        var formatted = state.header_data.top3.map(item => `<a href='/topic/${ item.post_topic }'>#${ item.post_topic }</a>`)
        return formatted.join(' ') + ` <a href='/topics/'>more&raquo;</a>`
    }

    if (typeof pages[state.page] === 'function') { // hit the db iff the request is for a valid request
        try {
            await get_connection_from_pool(state)
            await block_countries(state)
            await block_nuked(state)
            await collect_post_data(state)
            await set_user(state)
            await pages[state.page](state)
        }
        catch(e) { console.log(e); send_html(500, e.message, state) }
    }
    else {
        let err = `${ state.req.url } is not a valid request`
        console.log(err)
        send_html(404, err, state)
    }

} // end of render
