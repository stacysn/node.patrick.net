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

locks = {} // global locks to allow only one db connection per ip; helps mitigate dos attacks

pool = mysql.createPool(conf.db)
pool.on('release', db => { // delete the lock for the released db.threadId, and any locks that are older than 2000 milliseconds
    Object.keys(locks).map(ip => {
        if (locks[ip].threadId == db.threadId || locks[ip].ts < (Date.now() - 2000)) {
            delete locks[ip]
            console.log(`unlock for ${ ip }`)
        }
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

        // query or set a database lock for this ip; each ip is allowed only one outstanding connection at a time
        state.ip = state.req.headers['x-forwarded-for']

        if (locks[state.ip]) {
            //send_html(403, 'Rate Limit Exceeded')
            console.log(`Rate limit exceeded by ${ state.ip } by asking for ${ state.req.url }`)
            reject(state)
        }

        pool.getConnection(function(err, db) {

            state.db = db

            locks[state.ip] = { // set the lock
                threadId : db.threadId,
                ts       : Date.now()
            }
            console.log(`dblock for ${ state.ip } when asking for ${ state.req.url }`)

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

        if (0 == results.length) state.current_user = null
        else                     state.current_user = results[0]

        // update users currently online for display in header
        await query(`delete from onlines where online_last_view < date_sub(now(), interval 5 minute)`, null, state)
        await query(`insert into onlines (online_user_id, online_username, online_last_view) values (?, ?, now())
                     on duplicate key update online_last_view=now()`, [state.current_user.user_id, state.current_user.user_name], state)

    }
    catch(e) { // no valid cookie
        state.current_user = null
    }
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

async function send_login_link(state) {

	if (!/^\w.*@.+\.\w+$/.test(state.post_data.user_email)) return 'Please go back and enter a valid email'

    baseurl  = (/^dev\./.test(os.hostname())) ? conf.baseurl_dev : conf.baseurl // conf.baseurl_dev is for testing email
    console.log(`baseurl is ${baseurl}`)
    key      = md5(Date.now() + conf.nonce_secret)
    key_link = `${ baseurl }/key_login?key=${ key }`

    var results = await query('update users set user_activation_key=? where user_email=?', [key, state.post_data.user_email], state)

    if (results.changedRows) {

        let mailOptions = {
            from:    conf.admin_email,
            to:      state.post_data.user_email,
            subject: `Your ${ conf.domain } login info`,
            html:    `Click here to log in and get your password: <a href='${ key_link }'>${ key_link }</a>`
        }

        get_transporter().sendMail(mailOptions, (error, info) => {
            if (error) console.log('error in send_login_link: ' + error)
            else       console.log('send_login_link %s sent: %s', info.messageId, info.response);
        })

        return 'Please check your email for the login link'
    }
    else return `Could not find user with email ${ state.post_data.user_email }`
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
    return url.parse(path).path.replace(/\?.*/,'').split('/').map(segment => segment.replace(/\W/g,''))
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

            send_html(200, content)
        },

        delete : async function() { // delete a comment

            var comment_id = segments(state.req.url)[2]

            if (!state.current_user) send_html(200, content) // do nothing if not logged in

            // delete comment only if current user is comment_author
            await query('delete from comments where comment_id = ? and comment_author = ?', [comment_id, state.current_user.user_id], state)

            send_html(200, '')
        },

        home : async function () {

            state.header_data = await header_data(state)

            let current_user_id = state.current_user ? state.current_user.user_id : 0

            // left joins to also get each post's viewing and voting data for the current user if there is one
            let sql = `select sql_calc_found_rows * from posts
                       left join postviews on postview_post_id=post_id and postview_user_id= ?
                       left join postvotes on postvote_post_id=post_id and postvote_user_id= ?
                       where post_modified > date_sub(now(), interval 7 day) and post_approved=1
                       order by post_modified desc limit 0, 20`

            state.posts = await query(sql, [current_user_id, current_user_id], state)

            let content = html(
                midpage(
                    post_list()
                )
            )

            send_html(200, content)
        },

        key_login : async function() {

            key      = url.parse(state.req.url, true).query.key
            password = md5(Date.now() + conf.nonce_secret).substring(0, 6)

            state.header_data = await header_data(state)

            var results = await query('select user_email from users where user_activation_key = ?', [key], state)

            if (results.length) {
                email = results[0].user_email

                // erase key so it cannot be used again, and set new password
                await query('update users set user_activation_key=null, user_pass=? where user_activation_key=?', [md5(password), key], state)

                login(state, email, password)
            }
            else {
                state.message     = `Darn, that key has already been used. Please try 'forgot password' if you need to log in.`

                let content = html(
                    midpage(
                        h1(),
                        text()
                    )
                )

                send_html(200, content)
            }
        },

        logout : async function() {

            state.current_user = null
            var d              = new Date()
            var html           = loginprompt(state)

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

        new_comment : async function() {

            post_data = state.post_data
            Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

            if (!post_data.comment_content) { send_html(200, ''); return } // empty comment

            // rate limit by user's ip address
            var results = await query('select (unix_timestamp(now()) - unix_timestamp(user_last_comment_time)) as ago from users where user_last_comment_time is not null and user_last_comment_ip = ? order by user_last_comment_time desc limit 1',
                [state.ip], state)

            if (results.length && results[0].ago < 2) { // this ip already commented less than two seconds ago
                state.message = 'You are posting comments too quickly! Please slow down'
                send_html(200, alert())
            }
            else {

                post_data.comment_author   = state.current_user ? state.current_user.user_id : 0
                post_data.comment_content  = post_data.comment_content.linkify() // linkify, imagify, etc
                post_data.comment_dislikes = 0
                post_data.comment_likes    = 0
                post_data.comment_approved = 1
                post_data.comment_date     = new Date().toISOString().slice(0, 19).replace('T', ' ') // mysql datetime format

                await query('update users set user_last_comment_ip = ? where user_id = ?', [state.ip, state.current_user.user_id], state)
                await query('update posts set post_modified = ? where post_id = ?', [post_data.comment_date, post_data.comment_post_id], state)
                await query('insert into comments set ?', post_data, state)

                // now select the inserted row so that we pick up the comment_date time and user data for displaying the comment
                var results = await query('select * from comments left join users on comment_author=user_id where comment_id = ?', [results.insertId], state)

                if (results.length) state.comment = results[0]

                send_html(200, comment(state.comment))
            }
        },

        new_post : async function() {

            post_data = state.post_data
            Object.keys(post_data).map(key => { post_data[key] = strip_tags(post_data[key]) })

            post_data.post_approved = 1 // create a function to check content before approving!

            await query('insert into posts set ?, post_modified=now()', post_data, state)

            redirect(`/post/${results.insertId}`)
        },

        post : async function() { // show a single post

            let post_id = segments(state.req.url)[2] // get post's db row number from url, eg 47 from /post/47/slug-goes-here

            var results = await query('select * from posts where post_id=?', [post_id], state)

            if (0 == results.length) send_html(404, `No post with id "${post_id}"`)
            else {
                state.post = results[0]

                state.header_data = await header_data(state)

                // pick up the comment list for this post
                var results = await query('select * from comments left join users on comment_author=user_id where comment_post_id = ? order by comment_date',
                    [post_id], state)

                if (results.length) state.comments = results

				if (state.current_user) {
					await query(`insert into postviews (postview_user_id, postview_post_id, postview_last_view)
                                 values (?, ?, now()) on duplicate key update postview_last_view=now()`, [state.current_user.user_id, post_id], state)
                }

                let content = html(
                    midpage(
                        post(),
                        comment_list(),
                        commentbox()
                    )
                )

                send_html(200, content)
            }
        },

        post_login : async function() {
            email    = state.post_data.email
            password = state.post_data.password

            login(state, email, password)
        },

        postform : async function() {

            state.header_data = await header_data(state)

            let content = html(
                midpage(
                    postform()
                )
            )

            send_html(200, content)
        },

        recoveryemail : async function() {

            state.header_data = await header_data(state)

            Object.keys(state.post_data).map(key => { state.post_data[key] = strip_tags(state.post_data[key]) })

            state.message = await send_login_link(state)

            let content = html(
                midpage(
                    h1(),
                    text()
                )
            )

            send_html(200, content)
        },

        registration : async function() {

            Object.keys(state.post_data).map(key => { state.post_data[key] = strip_tags(state.post_data[key]) })

            if (/\W/.test(state.post_data.user_name))               state.message = 'Please go back and enter username consisting only of letters'
            if (!/^\w.*@.+\.\w+$/.test(state.post_data.user_email)) state.message = 'Please go back and enter a valid email'

			if (!state.message) { // no error yet

				var results = await query('select * from users where user_email = ?', [state.post_data.user_email], state)

				if (results[0]) {
					state.message = `That email is already registered. Please use the "forgot password" link above.</a>`
				}
				else {
					let results = await query('select * from users where user_name = ?', [state.post_data.user_name], state)

					if (results[0]) state.message = `That user name is already registered. Please choose a different one.</a>`
					else {
						await query('insert into users set ?', state.post_data, state)
						state.message = await send_login_link(state)
					}
				}
			}

            let content = html(
                midpage(
                    h1(),
                    text()
                )
            )

            send_html(200, content)
        },

        since : async function() { // given a post_id and epoch timestamp, redirect to post's first comment after that timestamp

            // these will die on replace() if parm is not defined and that's the right thing to do
            let post_id = url.parse(state.req.url, true).query.p.replace(/\D/g,'')
            let since   = url.parse(state.req.url, true).query.since.replace(/\D/g,'')

			let results = await query(`select comment_id from comments
									   where comment_post_id = ? and comment_approved > 0 and comment_date > from_UNIXTIME(?)
									   order by comment_date limit 1`, [post_id, since], state)

			let c = results[0].comment_id

            redirect(`/post/${post_id}?c=${c}#comment-${c}`)
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

            send_html(200, content)
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

            send_html(200, content)
        },

        user : async function() {

            var user_name = segments(state.req.url)[2] // like /user/Patrick
            var sql       = 'select * from users where user_name=?'
            var sql_parms = [user_name]

            state.current_users = await query(sql, sql_parms, state)
            state.header_data   = await header_data(state)

            let content = html(
                midpage(
                    user_info()
                )
            )

            send_html(200, content)
        },

        users : async function() {

            state.header_data = await header_data(state)

            var sql       = 'select * from users limit 20'
            var sql_parms = null
            state.current_users = await query(sql, sql_parms, state)

            let content = html(
                midpage(
                    user_list()
                )
            )

            send_html(200, content)
        },

    } // end of pages /////////////////////////////////////////////////////////

    function about_this_site() {
        return `<h1>About ${ conf.domain }</h1>${ conf.domain } is the bomb!`
    }


    function alert() {
        return `<script type='text/javascript'> alert('${ state.message }'); </script>`
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

        if (state.current_user) {
            var del = state.current_user.user_id == c.comment_author ?
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
        var utz = state.current_user ? state.current_user.user_timezone : 'America/Los_Angeles'
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

    async function login(state, email, password) {

        var results = await query('select * from users where user_email = ? and user_pass = ?', [email, md5(password)], state)

        if (0 == results.length) {
            state.login_failed_email = email
            state.current_user       = null
            var user_id              = ''
            var user_pass            = ''
        }
        else {
            state.login_failed_email = null
            state.current_user       = results[0]
            var user_id              = state.current_user.user_id
            var user_pass            = state.current_user.user_pass
        }

        if ('post_login' == state.page) var content = icon_or_loginprompt(state)
        if ('key_login'  == state.page) {

            var current_user_id = state.current_user ? state.current_user.user_id : 0

            // left joins to also get each post's viewing and voting data for the current user if there is one
            let sql = `select sql_calc_found_rows * from posts
                       left join postviews on postview_post_id=post_id and postview_user_id= ?
                       left join postvotes on postvote_post_id=post_id and postvote_user_id= ?
                       where post_modified > date_sub(now(), interval 7 day) and post_approved=1
                       order by post_modified desc limit 0, 20`

            state.posts = await query(sql, [current_user_id, current_user_id], state)
            state.message = `Your password is ${ password } and you are now logged in`

            var content = html(
                midpage(
                    alert(),
                    post_list()
                )
            )
        }

        var usercookie = `${ conf.usercookie }=${ user_id   }`
        var pwcookie   = `${ conf.pwcookie   }=${ user_pass }`
        var d          = new Date()
        var decade     = new Date(d.getFullYear()+10, d.getMonth(), d.getDate()).toUTCString()

        // you must use the undocumented "array" feature of writeHead to set multiple cookies, because json
        var headers = [
            ['Content-Length' , content.length                            ],
            ['Content-Type'   , 'text/html'                               ],
            ['Expires'        , d.toUTCString()                           ],
            ['Set-Cookie'     , `${usercookie}; Expires=${decade}; Path=/`],
            ['Set-Cookie'     , `${pwcookie};   Expires=${decade}; Path=/`]
        ] // do not use 'secure' parm with cookie or will be unable to test login in dev, bc dev is http only

        state.res.writeHead(200, headers)
        state.res.end(content)
        if (state.db) state.db.release()
    }

    function midpage(...args) { // just an id so we can easily swap out the middle of the page
        return `<div id="midpage" >
            ${ args.join('') }
            </div>`
    }

    function new_post_button() {
        return '<a href="/postform" class="btn btn-success btn-sm" title="start a new post" ><b>new post</b></a>'
    }

    function post_link(post) {
        let path = post_path(post)
        return `<a href='${path}'>${post.post_title}</a>`
    }

    function post_path(post) {
        let slug = slugify(`${post.post_title}`)
        return `/post/${post.post_id}/${slug}`
    }

    function post_list() {

        // format and display a list of posts from whatever source; pass in only a limited number, because all of them will display

        if (state.posts) {
            var formatted = state.posts.map(post => {

                var link = post_link(post)
                var path = post_path(post)

                if (!state.current_user && post.post_title.match(/thunderdome/gi)) return '' // don't show thunderdome posts to non-logged-in users
                if (!state.current_user && post.post_nsfw)                         return '' // don't show porn posts to non-logged-in users

				net = post.post_likes - post.post_dislikes

				if (state.current_user) { // user is logged in

                    if (!post.postview_last_view)
                        var unread = `<a href='${path}' ><img src='/content/unread_post.gif' width='45' height='16' title='You never read this one' ></a>`
                    else 
                        var unread = unread_comments_icon(post, post.postview_last_view) // last view by this user, from left join

					var upgrey   = post.postvote_up   ? `style='color: grey; pointer-events: none;' title='you liked this'    ` : ``
					var downgrey = post.postvote_down ? `style='color: grey; pointer-events: none;' title='you disliked this' ` : ``

					var likelink    = `href='#' ${upgrey}   onclick='postlike('post_${post.post_id}');   return false;'`
					var dislikelink = `href='#' ${downgrey} onclick='postdislike('post_${post.post_id}');return false;'`
				}
				else {
					var likelink    = `href='#' onclick='midpage.innerHTML = registerform.innerHTML; return false'`
					var dislikelink = `href='#' onclick='midpage.innerHTML = registerform.innerHTML; return false'`
				}


                return `<div class='post' >
                    <div class='arrowbox' >
                        <a ${likelink} >&#9650;</a><br><span id='post_${post.post_id}' />${net}</span><br><a ${dislikelink} >&#9660;</a>
                    </div>
                    ${link} ${post.postview_last_view} ${post.post_comments} comments ${unread}

                </div>`
            })
        }
        else formatted = []

        return formatted.join('')
        /*


                $outbound_ref = '';
                if ($external_link = get_external_link($post->post_content)) {

                    $host = parse_url($external_link)['host'];
                    $host = $host ? $host : 'patrick.net';

                    $outbound_ref = " <a href='$external_link' target='_blank' title='original story at $host' ><img src='/images/ext_link.png'></a>";
                }

                if (!$current_user->user_hide_post_list_photos) {
                    $src = get_first_image($post->post_content);
                    if ($src) {
                        if ($post->post_nsfw)
                            print "<div class='icon' ><a href='$path' ><img src='/images/nsfw.png' border=0 width=100 align=top hspace=5 vspace=5 ></a></div>";
                        else
                            print "<div class='icon' ><a href='$path' ><img src='$src' border=0 width=100 align=top hspace=5 vspace=5 ></a></div>";
                    }
                }

                print "<a href='$path' ><b><font size='+1' $red >$post_title</font></b></a>$outbound_ref " . share_post($post) . '<br>';

                $dt_ts = new DateTime($post->post_date);
                $dt_ts->setTimeZone(new DateTimeZone('America/Los_Angeles')); // for now, california time for all users
                //$when = $dt_ts->format('D M j, Y');
                //$when = rel_time($post->post_date); // override the above line as experiment

                if ($tag = text2hashtag($post->post_content)) {

                    $tlink = " in <a href='/topics/$tag' >#$tag</a>";

                    if (0 == strlen($post->post_topic)) { // if post_topic not yet set for this post, set it to the tag now
                        $sql = "update posts set post_topic = '$tag' where post_id=$post->post_id";
                        $db->query($sql);
                    }
                }
                else $tlink = '';

                print "by " . name_posts($post->post_author) . $tlink . ' &nbsp; ';


                $post_comments = number_format(intval($post->post_comments));
                $ago = rel_time($post->post_modified);

                $s = $post->post_comments == 1 ? "" : "s";
                $path = post_id2path($post->post_id);

                if ($post->post_comments)
                    print "<a href='$path'>$post_comments&nbsp;comment$s</a>, latest <a href='$path#comment-$post->post_latest_comment_id' >$ago</a>";
                else
                    print "Posted $ago";

                print " $unread <br>";

                $content = $post->post_content;
                list($content, $more_wc) = first_words( strip_tags($content), 30 );
                if ($more_wc) $content .= "... ";
                if ($content) print "<font size='-1'>$content</font>";
                print "</div>";
            }
        }
        */
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

	function unread_comments_icon(post, last_view) { // return the blinky icon if there are unread comments in a post

		// if post_modified > last time they viewed this post, then give them a link to earliest unread comment
		let last_viewed = Date.parse(last_view) / 1000
		let modified    = Date.parse(post.post_modified) / 1000

		if (modified > last_viewed) {

			let path = post_path(post)
			let unread = `<a href='${path}?since=${last_viewed}' ><img src='/content/unread_comments.gif' width='19' height='18' title='View unread comments'></A>`

			return unread
		}
		else return ''
	}

    function user_list() {

        var formatted = state.users.map( (item) => {
            return `<div class='user' ><a href='/user/${ item.user_name }'>${ item.user_name }</a></div>`
        })

        return formatted.join('')
    }

    function user_icon(u, scale=1) {

        user_icon_width  = Math.round(u.user_icon_width  * scale)
        user_icon_height = Math.round(u.user_icon_height * scale)

        return u.user_icon ? `<img src='${u.user_icon}' width='${user_icon_width}' height='${user_icon_height}' >` : ''
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
        if (state.current_user) return id_box(state)
        else                    return loginprompt(state)
    }

    function id_box() {

        var img = user_icon(state.current_user, 0.5) // scale image down

        return `
            <div id='status' >
                <a href='/user/${state.current_user.user_name}' >${img} ${state.current_user.user_name}</a>
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
                <div class='form-group'><input type='text' name='user_email'      placeholder='email'     class='form-control'                ></div>
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

	function redirect(redirect_to) {

		var message = `Redirecting to ${ redirect_to }`

		var headers =  {
			'Location'       : redirect_to,
			'Content-Length' : message.length,
			'Expires'        : new Date().toUTCString()
		}

		state.res.writeHead(303, headers)
		state.res.end(message)
		if (state.db) state.db.release()
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

	function die(message) { // errors that normal user will never see

		var headers =  {
			'Content-Length' : message.length,
			'Expires'        : new Date().toUTCString()
		}

		state.res.writeHead(303, headers)
		state.res.end(message)
		console.log(message)
		if (state.db) state.db.release()
	}

	function send_html(code, html) {

		var headers =  {
			'Content-Type'   : 'text/html',
			'Content-Length' : html.length,
			'Expires'        : new Date().toUTCString()
		}

		state.res.writeHead(code, headers)
		state.res.end(html)
		if (state.db) state.db.release()
	}

    if (typeof pages[state.page] === 'function') { // hit the db iff the request is for a valid url
        try {
            await get_connection_from_pool(state)
            await block_countries(state)
            await block_nuked(state)
            await collect_post_data(state)
            await set_user(state)
            await pages[state.page](state)
        }
        catch(e) { console.log(e); send_html(500, e.message) }
    }
    else {
        let err = `${ state.req.url } is not a valid url`
        console.log(err)
        send_html(404, err)
    }

} // end of render
