// copyright 2017 by Patrick Killelea under the GPLv2 license

// globals are capitalized
try { CONF = require('./conf.json') } catch(e) { console.log(e.message); process.exit(1) } // conf.json is required

CHEERIO     = require('cheerio')         // via npm to parse html
CLUSTER     = require('cluster')
CRYPTO      = require('crypto')
FORMIDABLE  = require('formidable')      // via npm for image uploading
FS          = require('fs')
HTTP        = require('http')
JSDOM       = require('jsdom').JSDOM
MOMENT      = require('moment-timezone') // via npm for time parsing
MYSQL       = require('mysql')           // via npm to interface to mysql
NODEMAILER  = require('nodemailer')      // via npm to send emails
OS          = require('os')
QUERYSTRING = require('querystring')
URL         = require('url')

BASEURL     = (/^dev\./.test(OS.hostname())) ? CONF.baseurl_dev : CONF.baseurl // CONF.baseurl_dev is for testing, 'like http://dev' locally
LOCKS       = {}                         // db locks to allow only one db connection per ip; helps mitigate dos attacks

POOL = MYSQL.createPool(CONF.db)
POOL.on('release', db => { // delete the lock for the released db.threadId, and any locks that are older than 2000 milliseconds
    Object.keys(LOCKS).map(ip => {
        if (LOCKS[ip].threadId === db.threadId || LOCKS[ip].ts < (Date.now() - 2000)) {
            delete LOCKS[ip]
            //console.log(`unlock for ${ ip }`)
        }
    })
})
// end of globals

if (CLUSTER.isMaster) {
    for (var i = 0; i < OS.cpus().length; i++) CLUSTER.fork()

    CLUSTER.on('exit', function(worker, code, signal) {
        console.log(`worker pid ${worker.process.pid} died with code ${code} from signal ${signal}, replacing that worker`)
        CLUSTER.fork()
    })
} else HTTP.createServer(run).listen(CONF.http_port)

// end of top-level code; everything below is in a function

function run(req, res) { // handle a single http request

    var state = { // start accumulation of state for this request
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

        if (LOCKS[state.ip]) {
            console.log(`Rate limit exceeded by ${ state.ip } by asking for ${state.req.url}, threadId is ${LOCKS[state.ip].threadId}`)
            reject(false)
            throw { code : 403, message : 'rate limit exceeded' }
        }

        POOL.getConnection(function(err, db) {

            state.db = db

            LOCKS[state.ip] = { // set the lock
                threadId : db.threadId,
                ts       : Date.now()
            }
            //console.log(`dblock for ${state.ip} when asking for ${state.req.url}`)

            fulfill(true)
        })
    })
}

async function block_countries(state) { // block entire countries like Russia because all comments from there are inevitably spam

    var evil = await get_var('select country_evil from countries where inet_aton(?) >= country_start and inet_aton(?) <= country_end',
                                [state.ip, state.ip], state)

    if (evil) throw { code : 403, message : 'permission denied' }
}

async function block_nuked(state) { // block nuked users, usually spammers

    if (await get_var('select count(*) as c from nukes where nuke_ip = ?', [state.ip], state))
    throw { code : 403, message : 'permission denied' }
}

async function header_data(state) { // data that the page header needs to render
    state.header_data = {
        comments : await get_var(`select count(*) as c from comments`,                                     null, state), // int
        onlines  : await query(`select * from onlines order by online_username`,                           null, state), // obj
        //top3     : await query(`select post_topic, count(*) as c from posts
        //                        where length(post_topic) > 0 group by post_topic order by c desc limit 3`, null, state), // obj
        tot      : await get_var(`select count(*) as c from users`,                                        null, state), // int
    }
}

function collect_post_data(state) { // if there is any POST data, accumulate it and return it in fulfill()

    return new Promise(function(fulfill, reject) {

        if (state.req.method === 'POST') {
            var body = ''

            state.req.on('data', function (data) {
                body += data

                if (body.length > 1e6) { // too much POST data, kill the connection
                    state.req.connection.destroy()
                    throw { code : 413, message : 'Too much POST data', }
                }
            })

            state.req.on('end', function () { fulfill( QUERYSTRING.parse(body) ) })
        }
        else reject()
    })
}

async function collect_post_data_and_trim(state) { // to deal with safari on iphone tacking on unwanted whitespace to post form data
    let post_data = await collect_post_data(state)
    Object.keys(post_data).forEach(key => { post_data[key] = post_data[key].trim() })
    return post_data
}

async function set_user(state) { // update state with whether they are logged in or not

    try {
        var pairs = []

        state.req.headers.cookie.replace(/\s/g,'').split(';').forEach(function(element) {
            var name  = element.split('=')[0]
            var value = element.split('=')[1]

            pairs[name] = value
        })

        state.current_user = await get_row('select * from users where user_id = ? and user_pass = ?',
                                           [pairs[CONF.usercookie], pairs[CONF.pwcookie]], state)
        await set_relations(state)
        await set_topics(state)

        // update users currently online for display in header
        await query(`delete from onlines where online_last_view < date_sub(now(), interval 5 minute)`, null, state)
        await query(`insert into onlines (online_user_id, online_username, online_last_view) values (?, ?, now())
                     on duplicate key update online_last_view=now()`, [state.current_user.user_id, state.current_user.user_name], state)

    }
    catch(e) { // no valid cookie
        state.current_user = null
    }
}

async function set_relations(state) { // update state object with their relationships to other users
    // todo: eventually cache this data so we don't do the query on each hit
    if (state.current_user) {

        let non_trivial = `rel_my_friend > 0 or rel_i_ban > 0 or rel_i_follow > 0`
        let my_pov      = `select * from relationships
                           left join users on users.user_id=relationships.rel_other_id where rel_self_id = ? and (${non_trivial})`
        /*
        let other_pov   = `select rel_self_id   as t2_self_id,
                                  rel_other_id  as t2_other_id,
                                  rel_i_follow  as follows_me,
                                  rel_i_ban     as bans_me,
                                  rel_my_friend as likes_me
                                  from relationships where rel_other_id = ? and (${non_trivial})`

        // we have to both left join and right join to pick up cases where one side has relation but other does not
        let sql = `select * from (${my_pov}) as t1 left join  (${other_pov}) as t2 on t1.rel_other_id = t2.t2_self_id
                   union
                   select * from (${my_pov}) as t1 right join (${other_pov}) as t2 on t1.rel_other_id = t2.t2_self_id`

        var results2 = await query(sql, Array(4).fill(state.current_user.user_id), state)
        */

        var results = await query(my_pov, [state.current_user.user_id], state)

        state.current_user.relationships = [] // now renumber results array using user_ids to make later access easy

        for (var i = 0; i < results.length; ++i) state.current_user.relationships[results[i].rel_other_id] = results[i]
    }
}

async function set_topics(state) { // update state object with their topics they follow
    if (state.current_user) {
        var results = await query(`select topicwatch_name from topicwatches where topicwatch_user_id=?`, [state.current_user.user_id], state)
        state.current_user.topics = results.map(row => row.topicwatch_name)
    }
}

function md5(str) {
    var hash = CRYPTO.createHash('md5')
    hash.update(str)
    return hash.digest('hex')
}

function debug(s) { console.log(s) } // so that we can grep and remove lines from the source more easily

function intval(s) { // return integer from a string or float
    return parseInt(s) ? parseInt(s) : 0
}

function valid_email(e) {
    return /^\w.*@.+\.\w+$/.test(e)
}

function no_links(content) {

    let c = CHEERIO.load(content)

    if (!c('a').length) return 1
    else                return 0
}

function strip_tags(s) { // use like this: str = strip_tags('<p>There is some <u>text</u> here</p>', '<b><i><u><p><ol><ul>')

    // these are the only allowed tags that users can enter in posts or comments; they will not be stripped
    let allowed = '<a><b><blockquote><br><code><del><font><hr><i><iframe><img><li><ol><p><source><strike><sub><sup><u><ul><video><vsmall>'

    allowed = (((allowed || '') + '')
        .toLowerCase()
        .match(/<[a-z][a-z0-9]*>/g) || [])
        .join('') // making sure the allowed arg is a string containing only tags in lowercase (<a><b><c>)

    var tags = /<\/?([a-z][a-z0-9]*)\b[^>]*>/gi
    var commentsAndPhpTags = /<!--[\s\S]*?-->|<\?(?:php)?[\s\S]*?\?>/gi

    return s.replace(commentsAndPhpTags, '').replace(tags, function($0, $1) {
        return allowed.indexOf('<' + $1.toLowerCase() + '>') > -1 ? $0 : ''
    })
}

function strip_all_tags(s) {
    return s.replace(/(<([^>]+)>)/g,'')
}

function newlineify(s) { // transform the html shown in the edit box to be more human-friendly
    return s.replace(/<br>/gim, '\n')
            .replace(/<p>/gim,  '\n')
            .replace(/<\/p>/gim, '')
}

function first_words(string, num) {

    string = strip_all_tags(string)

    let allwords   = string.split(/\s+/).map(s => s.substring(0, 30)) // max single word len is 30 chars
    let firstwords = allwords.slice(0, num)

    if (allwords.length > firstwords.length) return firstwords.join(' ') + '...'
    else                                     return firstwords.join(' ')
}

function get_transporter() {
    return NODEMAILER.createTransport({
        host:   CONF.email.host,
        port:   CONF.email.port,
        secure: false, // do not use TLS
        auth: {
            user: CONF.email.user,
            pass: CONF.email.password
        },
        tls: {
            rejectUnauthorized: false // do not fail on invalid certs
        }
    })
}

function mail(email, subject, message) {

    if (!email) return // because sometimes we may try to mail a user with null for user_email in database

    let mailOptions = {
        from:    CONF.admin_email,
        to:      email,
        subject: subject,
        html:    message
    }

    get_transporter().sendMail(mailOptions, (error, info) => {
        if (error) console.log('error in mail: ' + error)
        else       console.log('%s sent: %s', info.messageId, info.response)
    })
}

Number.prototype.number_format = function() {
    return this.toLocaleString('en')
}

String.prototype.linkify = function(ref) {

    let hashtagPattern   = /^#(\w+)/gim
    let boldPattern      = / \*(.+)\*/gim
    let italicPattern    = / _(.+)_/gim
    let blockquotePattern= /""(.+)""/gim
    let imagePattern     = /((https?:\/\/[\w$%&~\/.\-;:=,?@\[\]+]*?)\.(jpg|jpeg|gif|gifv|png|bmp))(\s|$)/gim
    let urlPattern       = /\b(https?:\/\/[a-z0-9-+&@#\/%?=~_|!:,.;]*[a-z0-9-+&@#\/%=~_|])(\s|$)/gim // http://, https://
    let pseudoUrlPattern = /(^|[^\/])(www\.[\S]+(\b|$))(\s|$)/gim                                    // www. sans http:// or https://
    let emailpostPattern = /([\w.]+@[a-zA-Z_-]+?(?:\.[a-zA-Z]{2,6})+)\b(?!["<])/gim
    let linebreakPattern = /\n/gim
    let youtubePattern   = /(?:^|\s)[a-zA-Z\/\/:\.]*youtu(be.com\/watch\?v=|.be\/|be.com\/v\/|be.com\/embed\/)([a-zA-Z0-9\-_]+)([a-zA-Z0-9\/\*\-\_\?\&\;\%\=\.]*)/i
    let vimeoPattern     = /(?:^|\s)[a-zA-Z\/\/:\.]*(player.)?vimeo.com\/(video\/)?([a-zA-Z0-9]+)/i

    let result = this
        .trim()
        .replace(/\r/gim,          '')
        .replace(vimeoPattern,     '<iframe src="//player.vimeo.com/video/$3" width="500" height="375" frameborder="0" webkitallowfullscreen mozallowfullscreen allowfullscreen></iframe>')
        .replace(youtubePattern,   '<iframe width="500" height="375" src="//www.youtube.com/embed/$2$3" allowfullscreen></iframe>')
        .replace(hashtagPattern,   '<a href="/topic/$1">#$1</a>')
        .replace(imagePattern,     '<img src="$1"> ')
        .replace(urlPattern,       '<a href="$1">$1</a> ')
        .replace(pseudoUrlPattern, '$1<a href="http://$2">$2</a> ')
        .replace(emailpostPattern, '<a href="mailto:$1">$1</a> ')
        .replace(linebreakPattern, '<br>')
        .replace(boldPattern,      ' <b>$1</b>')
        .replace(italicPattern,    ' <i>$1</i>')
        .replace(blockquotePattern,'<blockquote>$1</blockquote>')
        .replace(/\0/g,            '') // do not allow null in strings

    result = block_unknown_iframes(result)
    result = sanitize_html(result)

    return result
}

function sanitize_html(s) {

    var allowed = { // with allowed attributes as an array
        'a'          : ['href', 'title', 'rel', 'rev', 'name'],
        'b'          : [],
        'blockquote' : [],
        'br'         : [],
        'code'       : [],
        'del'        : [],
        'font'       : ['color', 'face'],
        'hr'         : [],
        'i'          : [],
        'iframe'     : ['src', 'height', 'width'],
        'img'        : ['alt', 'align', 'border', 'height', 'hspace', 'longdesc', 'vspace', 'src', 'width'],
        'li'         : [],
        'ol'         : [],
        'ol'         : [],
        'p'          : [],
        'strike'     : [],
        'sub'        : [],
        'sup'        : [],
        'u'          : [],
        'ul'         : [],
        'video'      : ['width', 'height', 'name', 'src', 'controls'],
        'vsmall'     : [],
    }

    const dom = new JSDOM(s)

    for (tag in allowed) {
        let selection = dom.window.document.getElementsByTagName(tag)

        for (var i=0; i < selection.length; i++) {
            var item = selection[i]

            if (item.hasAttributes()) {
                for(var j = 0; j < item.attributes.length; j++) {
                    if (allowed[tag].indexOf(item.attributes[j].name) == -1) {
                        item.removeAttribute(item.attributes[j].name)
                    }
                }
            }
        }
    }

    return dom.serialize()
}

function block_unknown_iframes(s) { // special case: iframes are allowed, but only with vimeo and youtube src

    let $ = CHEERIO.load(s)

    if (!$('iframe').length)    return s // do nothing if there is no iframe in s

    if ($('iframe').length > 1) return 'please edit this and post just one video at a time, thanks'

    let matches = null

    if (matches = $('iframe').attr('src').match(/(https?:)?\/\/([\w\.]+)/)) {
        var host = matches[2]
    }
    else return '' // not a valid frame src

    if (/vimeo.com/.test(host) || /youtube.com/.test(host)) return s
    else return '' // only vimeo or youtube videos are allowed so far
}

function brandit(url) { // add ref=[domain name] to a url

    if (!url) return

    if (!new RegExp(CONF.domain).test(url)) { // brand it iff url does not already have CONF.domain in it somewhere

        let matches = null

        if (matches = url.match(/(.*)\?(.*)/)) { // if E parms, add in ref=CONF.domain as first one to make it visible and harder to remove
            let loc         = matches[1]
            let querystring = matches[2]
            url = `${loc}?ref=${CONF.domain}&${querystring}`
        }
        else if (matches = url.match(/(.*)#(.*)/)) { // if no parms, but E hash tag, add in brand BEFORE that
            let loc        = matches[1]
            let hashstring = matches[2]
            url = `${loc}?ref=${CONF.domain}#${hashstring}`
        }
        else { // Otherwise, we're the only parm.
            url = url + `?ref=${CONF.domain}`
        }
    }

    return url
}

async function get_row(sql, sql_parms, state) {
    let results = await query(sql, sql_parms, state)
    return results.length ? results[0] : null
}

async function get_var(sql, sql_parms, state) {
    let results = await query(sql, sql_parms, state)
    
    if (results.length) {
        let firstkey = Object.keys(results[0])
        return results[0][firstkey]
    }
    else return null
}

function query(sql, sql_parms, state) {

    return new Promise(function(fulfill, reject) {
        var query

        var get_results = function (error, results, fields, timing) { // callback to give to state.db.query()

            //debug(query.sql)

            if (error) {
                console.log(error)
                reject(error)
            }

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
    return URL.parse(path).path.replace(/\?.*/,'').split('/').map(segment => segment.replace(/[^\w%]/g,''))
}

function getimagesize(file) {
    return new Promise(function(fulfill, reject) {
        if (FS.existsSync(file)) {

            let { spawn } = require('child_process')
            let identify  = spawn('identify', ['-format', '%w %h', file]) // identify -format '%w %h' file

            identify.stdout.on('data', data => {
                let dims = data.toString('utf8').replace(/\n/,'').split(' ') // data is returned as string like '600 328\n'
                fulfill([dims[0], dims[1]]) // width and height
            })

            identify.stderr.on('data', data => { // remove the file because something is wrong with it
                FS.unlinkSync(file)
                console.log(`stderr from 'identify': ${data}`)
                reject('invalid image')
            })

            identify.on('close', code => {
                if (code > 0) { // if code is non-zero, remove the file because something is wrong with it
                    console.log(`code from 'identify': ${code}`)
                    FS.unlinkSync(file)
                    reject('invalid image')
                }
            })

        } else reject(`image not found: ${file}`)
    })
}

function resize_image(file, max_dim = 600) { // max_dim is maximum dimension in either direction
    return new Promise(function(fulfill, reject) {
        if (FS.existsSync(file)) {
            let { spawn } = require('child_process')
            let mogrify   = spawn('mogrify', ['-resize', max_dim, file]) // /usr/bin/mogrify -resize $max_dim $file

            mogrify.on('close', code => {
                if (code > 0) reject([null,null]) // todo: if code is non-zero, remove the file because something is wrong with it
                else          fulfill()
            })
        } else {
            console.log(`image not found: ${file}`)
            reject()
        }
    })
}

async function render(state) { /////////////////////////////////////////

    var pages = {

        about : async function() {
            redirect(`/post/${CONF.about_post_id}`)
        },

        accept_comment : async function() { // insert new comment

            if (!valid_nonce()) { // do not die, because that will return a whole html page to be appended into the #comment_list slot
                // show values for debugging nonce problems
                state.message = invalid_nonce_message()
                return send_html(200, popup())
            }

            let post_data = await collect_post_data_and_trim(state)

            if (!post_data.comment_content) return send_html(200, '') // empty comment

            // rate limit comment insertion by user's ip address
            var ago = await get_var(`select (unix_timestamp(now()) - unix_timestamp(user_last_comment_time)) as ago from users
                                     where user_last_comment_time is not null and user_last_comment_ip = ?
                                     order by user_last_comment_time desc limit 1`, [state.ip], state)

            if (ago && ago < 2) { // this ip already commented less than two seconds ago
                state.message = 'You are posting comments too quickly! Please slow down'
                return send_html(200, popup())
            }
            else {
                post_data.comment_author   = state.current_user ? state.current_user.user_id : 0
                post_data.comment_content  = strip_tags(post_data.comment_content.linkify())
                post_data.comment_dislikes = 0
                post_data.comment_likes    = 0
                post_data.comment_date     = new Date().toISOString().slice(0, 19).replace('T', ' ') // mysql datetime format
                post_data.comment_approved = state.current_user ? 1 : no_links(post_data.comment_content) // approve anon content if no links
 
                let insert_result = await query('insert into comments set ?', post_data, state)
                let comment_id = insert_result.insertId

                // now select the inserted row so that we pick up the comment_date time and user data for displaying the comment
                state.comment = await get_row('select * from comments left join users on comment_author=user_id where comment_id = ?',
                                              [comment_id], state)

                send_html(200, format_comment(state.comment)) // send html fragment

                comment_mail(state.comment)

                await query(`update posts set post_modified = ?,
                                              post_latest_comment_id = ?,
                                              post_comments=(select count(*) from comments where comment_post_id=?) where post_id = ?`,
                            [post_data.comment_date, comment_id, post_data.comment_post_id, post_data.comment_post_id], state)
                            // we select the count(*) from comments to make the comment counts self-correcting in case they get off somehow

                if (state.current_user) {

                    // update postviews so that user does not see his own comment as unread
                    await query(`insert into postviews (postview_user_id, postview_post_id, postview_last_view)
                                 values (?, ?, now()) on duplicate key update postview_last_view=now()`,
                                 [state.current_user.user_id, post_data.comment_post_id], state)

                    await query(`update users set user_last_comment_ip = ? where user_id = ?`, [state.ip, state.current_user.user_id], state)
                }

                if (!post_data.comment_approved) { // email moderator if comment not approved
                    mail(CONF.admin_email, 'new comment needs review',
                    `${post_data.comment_content}<p><a href='https://${CONF.domain}/comment_moderation'>moderation page</a>`)
                }
            }
        },

        accept_edited_comment : async function() { // update old comment

            if (!valid_nonce()) return die(invalid_nonce_message())

            let post_data = await collect_post_data_and_trim(state)

            if (!post_data.comment_content) return die('please go back and enter some content')

            // rate limit by user's ip address
            var ago = await get_var('select (unix_timestamp(now()) - unix_timestamp(user_last_comment_time)) as ago from users where user_last_comment_time is not null and user_last_comment_ip = ? order by user_last_comment_time desc limit 1',
                [state.ip], state)

            if (ago && ago < 2) { // this ip already commented less than two seconds ago
                return die('You are posting comments too quickly! Please slow down')
            }
            else {
                post_data.comment_content  = strip_tags(post_data.comment_content.linkify())
                post_data.comment_dislikes = 0
                post_data.comment_likes    = 0
                post_data.comment_approved = 1
 
                let comment_id = post_data.comment_id
                await query('update comments set ? where comment_id = ? and (comment_author = ? or 1 = ?)',
                            [post_data, comment_id, state.current_user.user_id, state.current_user.user_id], state)

                // now select the inserted row so that we pick up the comment_post_id
                state.comment = await get_row('select * from comments where comment_id = ?', [comment_id], state)

                if (state.comment.comment_adhom_when) redirect(`/comment_jail#comment-${comment_id}`)
                else {
                    let offset = await cid2offset(state.comment.comment_post_id, comment_id)
                    redirect(`/post/${state.comment.comment_post_id}?offset=${offset}#comment-${comment_id}`)
                }
            }
        },

        accept_post : async function() { // insert new post or update old post

            let post_data           = await collect_post_data_and_trim(state)
            post_data.post_content  = strip_tags(post_data.post_content.linkify()) // remove all but a small set of allowed html tags
            post_data.post_approved = state.current_user ? 1 : 0 // not logged in posts go into moderation
            delete post_data.submit

            if (matches = post_data.post_content.match(/#(\w+)/)) post_data.post_topic = matches[1] // first tag in the post becomes topic
            else                                                  post_data.post_topic = 'misc'

            if (intval(post_data.post_id)) { // editing old post, do not update post_modified time because it confuses users
                await query('update posts set ? where post_id=?', [post_data, intval(post_data.post_id)], state)
                var p = intval(post_data.post_id)
            }
            else { // new post
                post_data.post_author = state.current_user ? state.current_user.user_id : 0
                try {
                    var results = await query('insert into posts set ?, post_modified=now()', post_data, state)
                }
                catch (e) {
                    return die(e)
                }
                var p = results.insertId
            }

            if (!post_data.post_approved) {
                mail(CONF.admin_email, 'new post needs review',
                    `${post_data.post_content}<p><a href='https://${CONF.domain}/post_moderation'>post moderation page</a>`)

                return die(`The moderator will approve your post soon`)
            }

            redirect(`/post/${p}`)
        },

        approve_comment : async function() {

            let comment_id = intval(_GET('comment_id'))

            if (!comment_id)                        return send_html(200, '')
            if (!state.current_user)                return send_html(200, '')
            if (state.current_user.user_level !== 4) return send_html(200, '')
            if (!valid_nonce())                     return send_html(200, '')

            await query('update comments set comment_approved=1, comment_date=now() where comment_id=?', [comment_id], state)
            await query('update posts set post_modified=now() where post_id=(select comment_post_id from comments where comment_id=?)',
                        [comment_id], state)

            send_html(200, '') // make it disappear from comment_moderation page
        },

        approve_post : async function() {

            let post_id = intval(_GET('post_id'))

            if (!post_id)                            return send_html(200, '')
            if (!state.current_user)                 return send_html(200, '')
            if (state.current_user.user_level !== 4) return send_html(200, '')
            if (!valid_nonce())                      return send_html(200, '')

            await query('update posts set post_approved=1, post_modified=now() where post_id=?', [post_id], state)

            send_html(200, '') // make it disappear from post_moderation page
        },

        autowatch : async function() {

            var current_user_id = state.current_user ? state.current_user.user_id : 0

            if (!current_user_id) die('must be logged in to stop watching all posts')

            // left joins to also get each post's viewing and voting data for the current user if there is one
            let sql = `update postviews set postview_want_email=0 where postview_user_id = ?`
            await query(sql, [current_user_id], state)
            state.message = `All email of new post comments turned off`

            var content = html(
                midpage(
                    h1()
                )
            )

            return send_html(200, content)
        },

        best : async function() {

            if ('true' === _GET('all')) {
                var sql = `select * from comments left join users on user_id=comment_author where comment_likes > 3
                           order by comment_likes desc limit 40`

                var m = `<h2>best comments of all time</h2>or view the <a href='/best'>last week's</a> best comments<p>`
            }
            else {
                var sql = `select * from comments left join users on user_id=comment_author where comment_likes > 3
                           and comment_date > date_sub(now(), interval 7 day) order by comment_likes desc limit 40`

                var m = `<h2>best comments in the last week</h2>or view the <a href='/best?all=true'>all-time</a> best comments<p>`
            }

            state.comments = await query(sql, [], state)

            let offset = 0
            state.comments = state.comments.map(comment => { comment.row_number = ++offset; return comment })

            let content = html(
                midpage(
                    m,
                    comment_list()
                )
            )

            return send_html(200, content)
        },

        comment_jail : async function() { // no pagination, just most recent 80

            // comments not freed in 30 days will be deleted
            await query(`delete from comments where comment_adhom_when < date_sub(now(), interval 30 day)`, [], state)

            state.comments = await query(`select sql_calc_found_rows * from comments
                                          left join users on user_id=comment_author
                                          where comment_adhom_when is not null order by comment_date desc`, [], state)

            let offset = 0
            state.comments = state.comments.map(comment => { comment.row_number = ++offset; return comment })

            state.message = 'Uncivil Comment Jail'

            let content = html(
                midpage(
                    h1(),
                    'These comments were marked as uncivil. Patrick will review them and liberate comments which do not deserve to be here. You can edit your comment here to make it more civil and get it out of jail after the edits are reviewed. Comments not freed within 30 days will be deleted.',
                    comment_list()
                )
            )

            return send_html(200, content)
        },

        comment_moderation : async function() {

            if (!state.current_user) return die('you must be logged in to moderate comments')

            state.comments = await query(`select * from comments left join users on user_id=comment_author
                                          where comment_approved = 0`, [], state)

            let offset = 0
            state.comments = state.comments.map(comment => { comment.row_number = ++offset; return comment })

            state.message = 'comment moderation'

            let content = html(
                midpage(
                    h1(),
                    comment_list()
                )
            )

            return send_html(200, content)
        },

        comments : async function() { // show a list of comments by user, or by comment-frequence, or from a search

            let offset  = intval(_GET('offset'))
            let results = null

            if (_GET('a')) {      // a is author name
                let a         = decodeURIComponent(_GET('a').replace(/[^\w %]/, ''))
                results       = await get_comment_list_by_author(a, offset, 40)
                state.message = `<h2>${a}'s comments</h2>`
            }
            else if (_GET('n')) { // n is number of comments per author, so we can see all comments by one-comment authors, for example
                let n         = intval(_GET('n'))
                results       = await get_comment_list_by_number(n, offset, 40)
                state.message = `<h2>comments by users with ${n} comments</h2>`
            }
            else if (_GET('s')) { // comment search
                let s         = _GET('s').replace(/[^\w %]/, '')
                results       = await get_comment_list_by_search(s, offset, 40)
                state.message = `<h2>comments that contain "${s}"</h2>`
            }
            else return send_html(200, `invalid request`)

            state.comments            = results.comments
            state.comments.found_rows = results.total

            let content = html(
                midpage(
                    h1(),
                    comment_pagination(),
                    comment_list(),
                    comment_search_box()
                )
            )

            return send_html(200, content)
        },

        delete_comment : async function() { // delete a comment

            let comment_id = intval(_GET('comment_id'))
            let post_id    = intval(_GET('post_id'))

            if (!state.current_user)      return send_html(200, '')
            if (!valid_nonce())           return send_html(200, '')
            if (!(comment_id && post_id)) return send_html(200, '')

            await query('delete from comments where comment_id = ? and (comment_author = ? or 1 = ?)',
                        [comment_id, state.current_user.user_id, state.current_user.user_id], state)

            await reset_latest_comment(post_id)

            send_html(200, '')
        },

        delete_post : async function() { // delete a whole post, but not its comments

            if (!state.current_user) return die('you must be logged in to delete a post')
            if (!valid_nonce())      return die(invalid_nonce_message())

            if (post_id = intval(_GET('post_id'))) {

                let post = await get_row(`select * from posts where post_id = ?`, [post_id], state)
                if (!post) return die('no such post')

                // if it's their own post or if it's admin
                if ((state.current_user.user_id === post.post_author) || (state.current_user.user_id === 1)) {

                    let results = await query(`delete from posts where post_id = ?`, [post_id], state)
                    return die(`${results.affectedRows} post deleted`)
                }
                else return die('permission to delete post denied')
            }
            else return die('need a post_id')
        },

        dislike : async function() { // given a comment or post, downvote it

            if (!state.current_user) return `<a href='#' onclick="midpage.innerHTML = registerform.innerHTML; return false" >Please register</a>`

            if (intval(_GET('comment_id'))) {
                let comment_id = intval(_GET('comment_id'))
                let vote = await get_row(`select commentvote_up, count(*) as c from commentvotes
                                          where commentvote_user_id=? and commentvote_comment_id=?`,
                                          [state.current_user.user_id, comment_id], state)

                if (vote.c) { // already voted on this comment

                    let row = await get_row(`select * from comments where comment_id=?`, [comment_id], state)

                    return send_html(200, `&#8595;&nbsp; you dislike this (${row.comment_dislikes})`)
                }
                await query(`update comments set comment_dislikes=comment_dislikes+1 where comment_id=?`, [comment_id], state)

                await query(`insert into commentvotes (commentvote_user_id, commentvote_comment_id, commentvote_down) values (?, ?, 1)
                             on duplicate key update commentvote_up=1`, [state.current_user.user_id, comment_id], state)

                let comment_row = await get_row(`select * from comments where comment_id=?`, [comment_id], state)

                await query(`update users set user_dislikes=user_dislikes+1 where user_id=?`, [comment_row.comment_author], state)

                send_html(200, `&#8595;&nbsp;you dislike this (${comment_row.comment_dislikes})`)

                // no emailing done of dislikes

                // Now if Patrick was the disliker, then the user gets a bias bump down.
                if (1 === state.current_user.user_id) {
                    await query(`update users set user_pbias=user_pbias-1 where user_id=?`, [comment_row.comment_author], state)
                }
            }
            else if (intval(_GET('post_id'))) {
                let post_id = intval(_GET('post_id'))

                let vote = await get_row(`select postvote_down, count(*) as c from postvotes
                                          where postvote_user_id=? and postvote_post_id=?`, [state.current_user.user_id, post_id], state)

                if (vote.c) { // if they have voted before on this, just return

                    let post_row = await get_row(`select * from posts where post_id=?`, [post_id], state)

                    return send_html(200, String(post_row.post_likes - post_row.post_dislikes))
                }

                await query(`update posts set post_dislikes=post_dislikes+1 where post_id=?`, [post_id], state)

                await query(`insert into postvotes (postvote_user_id, postvote_post_id, postvote_down) values (?, ?, 1)
                             on duplicate key update postvote_down=0`, [state.current_user.user_id, post_id], state)

                let post_row = await get_row(`select * from posts where post_id=?`, [post_id], state)

                await query(`update users set user_dislikes=user_dislikes+1 where user_id=?`, [post_row.post_author], state)

                return send_html(200, String(post_row.post_likes - post_row.post_dislikes))

                // no email done of post dislikes
            }
            else return send_html(200, '') // send empty string if no comment_id or post_id
        },

        edit_comment : async function () {

            if (!valid_nonce()) return die(invalid_nonce_message())

            let comment_id = intval(_GET('c'))
            state.comment = await get_row(`select * from comments left join users on user_id=comment_author
                                               where comment_id=?`, [comment_id], state)

            if (!state.comment) return send_html(404, `No comment with id "${comment_id}"`)
            else {

                let content = html(
                    midpage(
                        comment_edit_box()
                    )
                )

                send_html(200, content)
            }
        },

        edit_post : async function () {

            if (!valid_nonce()) return die(invalid_nonce_message())

            let post_id = intval(_GET('p'))
            state.post = await get_row(`select * from posts left join users on user_id=post_author where post_id=?`, [post_id], state)

            if (!state.post) return send_html(404, `No post with id "${post_id}"`)
            else {

                let content = html(
                    midpage(
                        post_form()
                    )
                )

                send_html(200, content)
            }
        },

        edit_profile : async function() {

            let content = html(
                midpage(
                    profile_form()
                )
            )

            send_html(200, content)
        },

        follow_topic : async function() { // get or turn off emails of posts in a topic; can be called as ajax or full page

            let ajax  = intval(_GET('ajax'))
            let topic = _GET('topic').replace(/\W/, '').toLowerCase()

            if (!topic)              return ajax ? send_html(200, '') : die('topic missing')
            if (!state.current_user) return ajax ? send_html(200, '') : die('must be logged in to follow or unfollow')
            if (!valid_nonce())      return ajax ? send_html(200, '') : die(invalid_nonce_message())

            if (intval(_GET('undo'))) {

                await query(`delete from topicwatches where topicwatch_name=? and topicwatch_user_id=?`,
                            [topic, state.current_user.user_id], state)
            }
            else {
                await query(`replace into topicwatches set topicwatch_start=now(), topicwatch_name=?, topicwatch_user_id=?`,
                            [topic, state.current_user.user_id], state)
            }

            // either way, output follow button with right state and update this user's follow count
            ajax ? send_html(200, follow_topic_button(topic)) : die('Follow status updated')
        },

        follow_user : async function() { // get or turn off emails of a user's new posts; can be called as ajax or full page

            let ajax     = intval(_GET('ajax'))
            let other_id = intval(_GET('other_id'))

            if (!other_id)           return ajax ? send_html(200, '') : die('other_id missing')
            if (!state.current_user) return ajax ? send_html(200, '') : die('must be logged in to follow or unfollow')
            if (!valid_nonce())      return ajax ? send_html(200, '') : die(invalid_nonce_message())

            if (intval(_GET('undo'))) {
                await query(`replace into relationships set rel_i_follow=0, rel_self_id=?, rel_other_id=?`,
                            [state.current_user.user_id, other_id], state)
            }
            else {
                await query(`replace into relationships set rel_i_follow=unix_timestamp(now()), rel_self_ID=?, rel_other_id=?`,
                            [state.current_user.user_id, other_id], state)
            }

            // either way, output follow button with right state and update this user's follow count
            ajax ? send_html(200, follow_user_button(await get_userrow(other_id))) : die('Follow status updated')

            await query(`update users set user_followers=(select count(*) from relationships where rel_i_follow > 0 and rel_other_id=?)
                         where user_id=?`, [other_id, other_id], state)
        },

        home : async function () {

            if (p = intval(_GET('p'))) return redirect(`/post/${p}`, 301) // legacy redirect for cases like /?p=1216301

            let current_user_id = state.current_user ? state.current_user.user_id : 0

            let [curpage, slimit, order, order_by] = page()

            // left joins to also get each post's viewing and voting data for the current user if there is one
            let sql = `select sql_calc_found_rows * from posts
                       left join postviews on postview_post_id=post_id and postview_user_id= ?
                       left join postvotes on postvote_post_id=post_id and postvote_user_id= ?
                       left join users     on user_id=post_author
                       where post_modified > date_sub(now(), interval 7 day) and post_approved=1
                       ${order_by} limit ${slimit}`

            state.posts = await query(sql, [current_user_id, current_user_id], state)

            let content = html(
                midpage(
                    tabs(order),
                    post_list(),
                    post_pagination(await sql_calc_found_rows(), curpage, `&order=${order}`)
                )
            )

            send_html(200, content)
        },

        ignore : async function() { // stop ignoring a user

            let other_id = intval(_GET('other_id'))

            if (!other_id)           return send_html(200, '')
            if (!state.current_user) return send_html(200, '')
            if (!valid_nonce())      return send_html(200, '')

            if (intval(_GET('undo'))) {
                await query(`replace into relationships set rel_i_ban=0, rel_self_id=?, rel_other_id=?`,
                            [state.current_user.user_id, other_id], state)

                send_html(200, '') // make the user disappear from edit_profile page
            }
            else {
                await query(`replace into relationships set rel_i_ban=unix_timestamp(now()), rel_self_ID=?, rel_other_ID=?`,
                            [state.current_user.user_id, other_id], state)

                send_html(200, '')
            }

            // either way, update this user's ignore count
            await query(`update users set user_bannedby=(select count(*) from relationships where rel_i_ban > 0 and rel_other_id=?)
                         where user_id=?`, [other_id, other_id], state)
        },

        key_login : async function() {

            let key      = _GET('key')
            let password = get_nonce(Date.now()).substring(0, 6)

            var email = await get_var('select user_email from users where user_activation_key = ?', [key], state)

            if (email) {

                // erase key so it cannot be used again, and set new password
                await query('update users set user_activation_key=null, user_pass=? where user_activation_key=?',
                            [md5(password), key], state)

                login(state, email, password)
            }
            else {
                state.message = `Darn, that key has already been used. Please try 'forgot password' if you need to log in.`

                let content = html(
                    midpage(
                        h1(),
                        text()
                    )
                )

                send_html(200, content)
            }
        },

        like : async function() { // given a comment or post, upvote it

            if (!state.current_user) return `<a href='#' onclick="midpage.innerHTML = registerform.innerHTML; return false" >Please register</a>`

            if (intval(_GET('comment_id'))) {
                let comment_id = intval(_GET('comment_id'))
                let vote = await get_row(`select commentvote_up, count(*) as c from commentvotes
                                          where commentvote_user_id=? and commentvote_comment_id=?`,
                                          [state.current_user.user_id, comment_id], state)

                if (vote && vote.c) { // already voted on this

                    let row = await get_row(`select * from comments where comment_id=?`, [comment_id], state)

                    return send_html(200, `&#8593;&nbsp; you like this (${row.comment_likes})`)
                }
                await query(`update comments set comment_likes=comment_likes+1 where comment_id=?`, [comment_id], state)

                await query(`insert into commentvotes (commentvote_user_id, commentvote_comment_id, commentvote_up) values (?, ?, 1)
                             on duplicate key update commentvote_up=1`, [state.current_user.user_id, comment_id], state)

                let comment_row = await get_row(`select * from comments where comment_id=?`, [comment_id], state)

                await query(`update users set user_likes=user_likes+1 where user_id=?`, [comment_row.comment_author], state)

                send_html(200, `&#8593;&nbsp;you like this (${comment_row.comment_likes})`)

                // Now mail the comment author that his comment was liked, iff he has user_summonable set
                // todo: AND if current user has no record of voting on this comment! (to prevent clicking like over and over to annoy author with email)
                let offset = await cid2offset(comment_row.comment_post_id, comment_row.comment_id)
                let comment_url = `https://${CONF.domain}/post/${comment_row.comment_post_id}?offset=${offset}#comment-${comment_row.comment_id}`

                let u = await get_row(`select * from users where user_id=?`, [comment_row.comment_author], state)

                if (intval(u.user_summonable)) {

                    let subject  = `${state.current_user.user_name} liked your comment`

                    let message = `<html><body><head><base href='https://${CONF.domain}/' ></head>
                    <a href='https://${CONF.domain}/user/${state.current_user.user_name}' >${state.current_user.user_name}</a>
                        liked the comment you made here:<p>\r\n\r\n
                    <a href='${comment_url}' >${comment_url}</a><p>${comment_row.comment_content}<p>\r\n\r\n
                    <font size='-1'>Stop getting <a href='https://${CONF.domain}/edit_profile#user_summonable'>notified of likes</a>
                    </font></body></html>`

                    mail(u.user_email, subject, message)
                }

                // Now if Patrick was the liker, then the user gets a bias bump up.
                if (1 === state.current_user.user_id) {
                    await query(`update users set user_pbias=user_pbias+1 where user_id=?`, [comment_row.comment_author], state)
                }
            }
            else if (intval(_GET('post_id'))) {
                let post_id = intval(_GET('post_id'))

                let vote = await get_row(`select postvote_up, count(*) as c from postvotes where postvote_user_id=? and postvote_post_id=?`,
                                      [state.current_user.user_id, post_id], state)

                if (vote && vote.c) { // if they have voted before on this, just return
                    let post_row = await get_row(`select * from posts where post_id=?`, [post_id], state)
                    return send_html(200, String(post_row.post_likes - post_row.post_dislikes))
                }

                await query(`update posts set post_likes=post_likes+1 where post_id=?`, [post_id], state)

                await query(`insert into postvotes (postvote_user_id, postvote_post_id, postvote_up) values (?, ?, 1)
                             on duplicate key update postvote_up=0`, [state.current_user.user_id, post_id], state)

                let post_row = await get_row(`select * from posts where post_id=?`, [post_id], state)

                await query(`update users set user_likes=user_likes+1 where user_id=?`, [post_row.post_author], state)

                send_html(200, String(post_row.post_likes - post_row.post_dislikes)) // don't return until we send email

                let post_url = 'https://' + CONF.domain +  post2path(post_row)

                let u = await get_row(`select * from users where user_id=?`, [post_row.post_author], state)

                if (intval(u.user_summonable)) {

                    let subject  = `${state.current_user.user_name} liked your post`

                    let message = `<html><body><head><base href='https://${CONF.domain}/' ></head>
                    <a href='https://${CONF.domain}/user/${state.current_user.user_name}' >${state.current_user.user_name}</a>
                        liked the post you made here:<p>\r\n\r\n
                    <a href='${post_url}' >${post_url}</a><p>${post_row.post_content}<p>\r\n\r\n
                    <font size='-1'>Stop getting <a href='https://${CONF.domain}/edit_profile#user_summonable'>notified of likes</a>
                    </font></body></html>`

                    mail(u.user_email, subject, message)
                }
            }
            else return send_html(200, '') // send empty string if no comment_id or post_id
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
                ['Set-Cookie'     , `${ CONF.usercookie }=_; Expires=${d}; Path=/`],
                ['Set-Cookie'     , `${ CONF.pwcookie   }=_; Expires=${d}; Path=/`]
            ] // do not use 'secure' parm with cookie or will be unable to test login in dev, bc dev is http only

            send(200, headers, html)
        },

        new_post : async function() {

            let content = html(
                midpage(
                    post_form()
                )
            )

            send_html(200, content)
        },

        nuke : async function() { // given a user ID, nuke all his posts, comments, and his ID

            let nuke_id = intval(_GET('nuke_id'))
            let u = await get_userrow(nuke_id)

            if (!valid_nonce())                   return die(invalid_nonce_message())
            if (1 !== state.current_user.user_id) return die('permission denied')
            if (1 === nuke_id)                    return die('admin cannot nuke himself')
            if (u.user_comments > 3)              return die('cannot nuke user with more than 3 comments')

            let country = await ip2country(u.user_last_comment_ip)

            await query(`insert into nukes (nuke_date, nuke_email, nuke_username, nuke_ip,  nuke_country) values
                                           (    now(),          ?,             ?,       ?,             ?)`,
                        [u.user_email, u.user_name, u.user_last_comment_ip, country], state)

            let rows = await query('select distinct comment_post_id from comments where comment_author=?', [nuke_id], state)

            for (var i=0; i<rows.length; i++) {
                let row = rows[i]
                await query('delete from comments where comment_post_id=? and comment_author=?', [row.comment_post_id, nuke_id], state)
                await reset_latest_comment(row.comment_post_id)
            }
            await query('delete from posts     where post_author=?',      [nuke_id], state)
            await query('delete from postviews where postview_user_id=?', [nuke_id], state)
            await query('delete from users     where user_id=?',          [nuke_id], state)

            redirect(state.req.headers.referer) 
        },

        post : async function() { // show a single post and its comments

            let current_user_id = state.current_user ? state.current_user.user_id : 0
            let post_id         = intval(segments(state.req.url)[2]) // get post's db row number from url, eg 47 from /post/47/slug-goes-here

            state.post = await get_row(`select * from posts
                                        left join postvotes on (postvote_post_id=post_id and postvote_user_id=?)
                                        left join postviews on (postview_post_id=post_id and postview_user_id=?)
                                        left join users on user_id=post_author
                                        where post_id=?`, [current_user_id, current_user_id, post_id], state)

            if (!state.post) return send_html(404, `No post with id "${post_id}"`)
            else {
                state.comments            = await post_comment_list(state.post) // pick up the comment list for this post
                state.comments.found_rows = await sql_calc_found_rows()
                state.post.watchers       = await get_var(`select count(*) as c from postviews
                                                           where postview_post_id=? and postview_want_email=1`, [post_id], state)

                state.post.post_views++ // increment here for display and in db on next line as record
                await query(`update posts set post_views = ? where post_id=?`, [state.post.post_views, post_id], state)

                if (current_user_id) {
                    state.post.postview_want_email = state.post.postview_want_email || 0 // keep as 1 or 0 from db; set to 0 if null in db
                    if( '0' == _GET('want_email') ) state.post.postview_want_email = 0

                    await query(`replace into postviews set
                                 postview_user_id=?, postview_post_id=?, postview_last_view=now(), postview_want_email=?`,
                                 [ current_user_id, post_id, state.post.postview_want_email ], state)
                }

                state.post.prev = intval(await get_var(`select max(post_id) as prev from posts where post_topic=? and post_id < ? limit 1`,
                                                  [state.post.post_topic, state.post.post_id], state))

                state.post.next = intval(await get_var(`select min(post_id) as next from posts where post_topic=? and post_id > ? limit 1`,
                                                  [state.post.post_topic, state.post.post_id], state))

                let content = html(
                    midpage(
                        topic_nav(),
                        post(),
                        comment_pagination(),
                        comment_list(), // mysql offset is greatest item number to ignore, next item is first returned
                        comment_pagination(),
                        comment_box()
                    )
                )

                send_html(200, content)
            }
        },

        post_login : async function() {

            let post_data = await collect_post_data_and_trim(state)

            login(state, post_data.email, post_data.password)
        },

        post_moderation : async function () {

            if (!state.current_user) return die('you must be logged in to moderate posts')

            state.posts = await query(`select * from posts left join users on user_id=post_author where post_approved=0`, [], state)

            let content = html(
                midpage(
                    post_list()
                )
            )

            send_html(200, content)
        },

        random : async function() {

            let rand = await get_var(`select round(rand() * (select count(*) from posts)) as r`, [], state)
            let p    = await get_var(`select post_id from posts limit 1 offset ?`, [rand], state)

            redirect(`/post/${p}`)
        },

        recoveryemail : async function() {

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

            let post_data = await collect_post_data_and_trim(state)

            if (/\W/.test(post_data.user_name))     state.message = 'Please go back and enter username consisting only of letters'
            if (!valid_email(post_data.user_email)) state.message = 'Please go back and enter a valid email'

            if (!state.message) { // no error yet

                if (await get_row('select * from users where user_email = ?', [post_data.user_email], state)) {
                    state.message = `That email is already registered. Please use the "forgot password" link above.</a>`
                }
                else {
                    if (await get_row('select * from users where user_name = ?', [post_data.user_name], state)) {
                        state.message = `That user name is already registered. Please choose a different one.</a>`
                    }
                    else {
                        await query('insert into users set user_registered=now(), ?', post_data, state)
                        state.message = await send_login_link(state)
                    }
                }
            }

            let content = html(
                midpage(
                `<h2>${state.message}</h2>`,
                text()
                )
            )

            send_html(200, content)
        },

        search : async function() {

            // if (is_robot()) die('robots may not do searches')

            let s = _GET('s').trim().replace(/[^0-9a-z ]/gi, '') // allow only alphanum and spaces for now
            let us = encodeURI(s)

            if (!s) return die('You searched for nothing. It was found.')

            let [curpage, slimit, order, order_by] = page()

            // These match() requests require the existence of fulltext index:
            //      create fulltext index post_title_content_index on posts (post_title, post_content)

            let sql = `select sql_calc_found_rows * from posts
                       left join users on user_id=post_author
                       where match(post_title, post_content) against ('${s}') ${order_by} limit ${slimit}`

            state.posts    = await query(sql, [], state)
            let found_rows = sql_calc_found_rows()
            state.message  = `search results for "${s}"`

            let content = html(
                midpage(
                    h1(),
                    post_pagination(found_rows, curpage, `&s=${us}&order=${order}`),
                    tabs(order, `&s=${us}`),
                    post_list(),
                    post_pagination(found_rows, curpage, `&s=${us}&order=${order}`)
                )
            )

            send_html(200, content)
        },

        since : async function() { // given a post_id and epoch timestamp, redirect to post's first comment after that timestamp

            // these will die on replace() if p or when is not defined and that's the right thing to do
            let p    = intval(_GET('p'))
            let when = intval(_GET('when'))

            let c = await get_var(`select comment_id from comments
                                       where comment_post_id = ? and comment_approved > 0 and comment_date > from_unixtime(?)
                                       order by comment_date limit 1`, [p, when], state)

            let offset = await cid2offset(p, c)

            redirect(`/post/${p}?offset=${offset}#comment-${c}`)
        },

        topic : async function() {

            var topic = segments(state.req.url)[2] // like /topics/housing

            let [curpage, slimit, order, order_by] = page()

            let sql = `select sql_calc_found_rows * from posts
                       left join users on user_id=post_author
                       where post_topic = ? and post_approved=1 ${order_by} limit ${slimit}`

            state.posts = await query(sql, [topic], state)
            state.message = '#' + topic

            let content = html(
                midpage(
                    h1(),
                    follow_topic_button(topic),
                    tabs(order, `&topic=${topic}`),
                    post_list(),
                    post_pagination(sql_calc_found_rows(), curpage, `&topic=${topic}&order=${order}`)
                )
            )

            send_html(200, content)
        },

        topics : async function () {

            state.topics = await query(`select post_topic, count(*) as c from posts
                                        where length(post_topic) > 0 group by post_topic having c >=3 order by c desc`, null, state)

            state.message = 'Topics'
        
            let content = html(
                midpage(
                    h1(),
                    topic_list()
                )
            )

            send_html(200, content)
        },

        uncivil : async function() { // move a comment to comment jail, or a post to post moderation

            let comment_id = intval(_GET('c'))

            if (state.current_user && valid_nonce() && comment_id) {
                await query(`update comments set comment_adhom_reporter=?, comment_adhom_when=now()
                             where comment_id = ? and (comment_author = ? or 1 = ?)`,
                             [state.current_user.user_id, comment_id, state.current_user.user_id, state.current_user.user_id], state)
            }

            send_html(200, '') // blank response in all cases
        },

        update_profile : async function() { // accept data from profile_form

            if (!valid_nonce())      return die(invalid_nonce_message())
            if (!state.current_user) return die('must be logged in to update profile')

            let post_data = await collect_post_data_and_trim(state)

            if (/\W/.test(post_data.user_name))     return die('Please go back and enter username consisting only of letters')
            if (!valid_email(post_data.user_email)) return die('Please go back and enter a valid email')

            post_data.user_summonable            = intval(post_data.user_summonable)
            post_data.user_hide_post_list_photos = intval(post_data.user_hide_post_list_photos)

            post_data.user_aboutyou = strip_tags(post_data.user_aboutyou.linkify()) 

            await query(`update users set user_email                 = ?,
                                          user_name                  = ?,
                                          user_summonable            = ?,
                                          user_hide_post_list_photos = ?,
                                          user_aboutyou              = ?  where user_id = ?`,
                [post_data.user_email,
                 post_data.user_name,
                 post_data.user_summonable,
                 post_data.user_hide_post_list_photos,
                 post_data.user_aboutyou,
                 state.current_user.user_id], state).catch(error => {
                    if (error.code.match(/ER_DUP_ENTRY/)) return die(`Sorry, looks like someone already took that email or user name`)
                    else                                  return die(`Something went wrong with save`)
                 })

            redirect('/edit_profile?updated=true')
        },

        upload : async function() {

            if (!state.current_user) return die('you must be logged in to upload images')

            var form = new FORMIDABLE.IncomingForm()

            form.maxFieldsSize = 7 * 1024 * 1024 // max upload is 4MB, but this seems to fail; nginx config will block larger images anyway
            form.maxFields = 1                   // only one image at a time

            // todo: implement upload progress meter with this
            //form.on('progress', function(bytesReceived, bytesExpected) { console.log(`${bytesReceived}, ${bytesExpected}`) })

            form.parse(state.req, async function (err, fields, files) {
                let d        = new Date()
                let mm       = ('0' + (d.getMonth() + 1)).slice(-2)
                let url_path = `/${CONF.upload_dir}/${d.getFullYear()}/${mm}`
                let abs_path = `${CONF.doc_root}${url_path}`

                if (!FS.existsSync(abs_path)) FS.mkdirSync(abs_path)

                let clean_name = clean_upload_path(abs_path, files.image.name)

                // note that files.image.path includes filename at end
                FS.rename(files.image.path, `${abs_path}/${clean_name}`, async function (err) {
                    if (err) throw err

                    let addendum = ''
                    let dims     = await getimagesize(`${abs_path}/${clean_name}`).catch(error => { addendum = `"${error}"` })

                    if (state.req.headers.referer.match(/edit_profile/)) { // uploading user icon

                        await resize_image(`${abs_path}/${clean_name}`, max_dim = 80) // limit max width to 80 px
                        dims = await getimagesize(`${abs_path}/${clean_name}`)        // get the new reduced image dimensions

                        let id = state.current_user.user_id
                        await query(`update users set user_icon        = ? where user_id = ?`, [`${url_path}/${clean_name}`, id], state)
                        await query(`update users set user_icon_width  = ? where user_id = ?`, [dims[0],                     id], state)
                        await query(`update users set user_icon_height = ? where user_id = ?`, [dims[1],                     id], state)

                        return redirect('/edit_profile')
                    }
                    else { // uploading image link to post or comment text area
                        if (dims[0] > 600) {
                            await resize_image(`${abs_path}/${clean_name}`, max_dim = 600) // limit max width to 600 px
                            dims = await getimagesize(`${abs_path}/${clean_name}`)         // get the new reduced image dimensions
                        }
                        addendum = `"<img src='${url_path}/${clean_name}' width='${dims[0]}' height='${dims[1]}' >"`

                        let content = `
                            <html>
                                <script language="javascript" type="text/javascript">
                                    var textarea = parent.document.getElementById('ta');
                                    textarea.value = textarea.value + ${addendum};
                                </script>
                            </html>`

                        send_html(200, content)
                    }
                })
            })
        },

        user : async function() {

            let current_user_id = state.current_user ? state.current_user.user_id : 0
            let [curpage, slimit, order, order_by] = page()
            let user_name = decodeURIComponent(segments(state.req.url)[2]).replace(/[^\w._ -]/g, '') // like /user/Patrick
            let u = await get_row(`select * from users where user_name=?`, [user_name], state)

            if (!u) return die(`no such user: ${user_name} url is ${state.req.url}`)

            // left joins to also get each post's viewing and voting data for the current user if there is one
            let sql = `select sql_calc_found_rows * from posts
                       left join postviews on postview_post_id=post_id and postview_user_id= ?
                       left join postvotes on postvote_post_id=post_id and postvote_user_id= ?
                       left join users     on user_id=post_author
                       where post_approved=1 and user_id=?
                       ${order_by} limit ${slimit}`

            state.posts = await query(sql, [current_user_id, current_user_id, u.user_id], state)

            let found_rows = await sql_calc_found_rows()

            let content = html(
                midpage(
                    user_info(u),
                    tabs(order),
                    post_list(),
                    post_pagination(found_rows, curpage, `&order=${order}`),
                    admin_user(u)
                )
            )

            send_html(200, content)
        },

        users : async function() {

            let d  = _GET('d')  ? _GET('d').replace(/[^adesc]/, '').substring(0,4)  : 'desc' // asc or desc
            let ob = _GET('ob') ? _GET('ob').replace(/[^a-z_]/, '').substring(0,32) : 'user_comments' // order by

            if ( _GET('unrequited') ) {
                state.message = `Unrequited Friendship Requests For ${state.current_user.user_name}`

                // 1. Find all those IDs that asked to be friends with user_id.
                await query('create temporary table unrequited select * from relationships where rel_other_id=? and rel_my_friend > 0',
                      [state.current_user.user_id], state)

                // 2. Subtract all those for which there is the acceptance line.
                await query(`delete from unrequited where rel_self_id in
                      (select rel_other_id from relationships where rel_self_id=? and rel_my_friend > 0)`,
                      [state.current_user.user_id], state)
                
                state.users = await query(`select sql_calc_found_rows * from unrequited, users
                                           where unrequited.rel_self_id = users.user_id and user_id = ? limit 40 offset 0`,
                                          [state.current_user.user_id], state)
            }
            else if ( _GET('followersof') ) {
                let followersof = intval(_GET('followersof'))

                state.message = 'Followers of ' + (await get_userrow(followersof)).user_name

                state.users = await query(`select sql_calc_found_rows * from users
                    where user_id in (select rel_self_id from relationships where rel_other_id=? and rel_i_follow > 0)
                    order by ${ob} ${d} limit 40 offset 0`, [followersof, ob, d], state)

                // keep followers-count cache in users table correct
                await query('update users set user_followers=? where user_id=?', [state.users.length, followersof], state);
            }
            else if ( _GET('following') ) {
                let following = intval(_GET('following'))

                state.message = 'Users ' + (await get_userrow(following)).user_name + ' is Following'

                state.users = await query(`select sql_calc_found_rows * from users where user_id in
                                          (select rel_other_id from relationships where rel_self_id=? and rel_i_follow > 0)
                                           order by ${ob} ${d} limit 40 offset 0`, [following], state)
            }
            else if ( _GET('friendsof') ) {
                let friendsof = intval(_GET('friendsof'))

                state.message = 'Friends of ' + (await get_userrow(friendsof)).user_name

                state.users = await query(`select sql_calc_found_rows * from users where user_id in
                                          (select r1.rel_other_id from relationships as r1, relationships as r2 where
                                              r1.rel_self_id=? and
                                              r1.rel_self_id=r2.rel_other_id and
                                              r2.rel_self_id=r1.rel_other_id and
                                              r1.rel_my_friend > 0 and r2.rel_my_friend > 0)
                                          order by ${ob} ${d} limit 40 offset 0`, [friendsof, ob, d], state)

                await query(`update users set user_friends=? where user_id=?`,
                            [state.users.length, friendsof], state); // Keep friends-count cache correct.
            }
            else if ( _GET('user_name') ) {

                let user_name = _GET('user_name').replace(/[^a-zA-Z0-9._ -]/).substring(0, 40)
                user_name = user_name.replace('/_/', '\_') // bc _ is single-char wildcard in mysql matching.

                state.message = `Users With Names Like '${user_name}'`

                state.users = await query(`select sql_calc_found_rows * from users where user_name like '%${user_name}%'
                                           order by ${ob} ${d} limit 40 offset 0`, [ob, d], state)
            }
            else {
                state.message = 'users'
                state.users   = await query(`select sql_calc_found_rows * from users order by ${ob} ${d} limit 40 offset 0`, [], state)
            }

            let content = html(
                midpage(
                    h1(),
                    user_list()
                )
            )

            send_html(200, content)
        },

        watch : async function() { // toggle a watch from a post

            let post_id = intval(_GET('post_id'))

            if (!state.current_user) return send_html(200, '')
            if (!valid_nonce())      return send_html(200, '')
            if (!post_id)            return send_html(200, '')

            let postview_want_email = await get_var(`select postview_want_email from postviews
                                                     where postview_user_id=? and postview_post_id=?`,
                                                     [state.current_user.user_id, post_id], state)

            if (postview_want_email) var want_email = 0 // invert
            else                     var want_email = 1

            await query(`insert into postviews (postview_user_id, postview_post_id, postview_want_email) values (?, ?, ?)
                         on duplicate key update postview_want_email=?`,
                        [state.current_user.user_id, post_id, want_email, want_email], state)

            send_html(200, watch_indicator(want_email))
        },

    } // end of pages

    /////////////////////////////////////////////////////////
    // functions within render(), arranged alphabetically:
    /////////////////////////////////////////////////////////

    function about_this_site() {
        return `<h1>About ${ CONF.domain }</h1>${ CONF.domain } is the bomb!`
    }

    function admin_user(u) { // links to administer a user

        if (!state.current_user)                                    return ``
        if (state.current_user && state.current_user.user_id !== 1) return ``

        return `<hr>
            <a href='mailto:${u.user_email}'>email ${u.user_email}</a> &nbsp;
            <a href='https://whatismyipaddress.com/ip/${u.user_last_comment_ip}'>${u.user_last_comment_ip}</a> &nbsp;
            <a href='/user/${u.user_name}?become=1&${create_nonce_parms()}' >become ${u.user_name}</a> &nbsp;
            <a href='/nuke?nuke_id=${u.user_id}&${create_nonce_parms()}' onClick='javascript:return confirm("Really?")' >nuke</a> &nbsp;
            <hr>`
    }

    function arrowbox(post) { // output html for vote up/down arrows; takes a post left joined on user's votes for that post

        let net = post.post_likes - post.post_dislikes

        if (state.current_user) { // user is logged in
            var upgrey   = post.postvote_up   ? `style='color: grey; pointer-events: none;' title='you liked this'    ` : ``
            var downgrey = post.postvote_down ? `style='color: grey; pointer-events: none;' title='you disliked this' ` : ``

            var likelink    = `href='#' ${upgrey}   onclick="postlike('post_${post.post_id}');   return false;"`
            var dislikelink = `href='#' ${downgrey} onclick="postdislike('post_${post.post_id}');return false;"`
        }
        else {
            var likelink    = `href='#' onclick="midpage.innerHTML = registerform.innerHTML; return false;"`
            var dislikelink = `href='#' onclick="midpage.innerHTML = registerform.innerHTML; return false;"`
        }

        return `<div class='arrowbox' >
                <a ${likelink} >&#9650;</a><br><span id='post_${post.post_id}' />${net}</span><br><a ${dislikelink} >&#9660;</a>
                </div>`
    }

    function brag() {

        var online_list = state.header_data.onlines.map(u => `<a href='/user/${u.online_username}'>${u.online_username}</a>`).join(', ')

        return `${ state.header_data.comments.number_format() } comments by
                <a href='/users'>${ state.header_data.tot.number_format() } registered users</a>,
                ${ state.header_data.onlines.length } online now: ${ online_list }`
    }

    async function cid2offset(post_id, comment_id) { // given a comment_id, find the offset

        return await get_var(`select floor(count(*) / 40) * 40 as o from comments
                              where comment_post_id=? and comment_id < ? order by comment_id`, [post_id, comment_id], state)
    }

    function clean_upload_path(path, filename) {

        if (!state.current_user) return ''

        // allow only alphanum, dot, dash in image name to mitigate scripting tricks
        // lowercase upload names so we don't get collisions on stupid case-insensitive Mac fs between eg "This.jpg" and "this.jpg"
        filename = filename.replace(/[^\w\.-]/gi, '').toLowerCase()

        let ext     = null
        let matches = null
        if (matches = filename.match(/(\.\w{3,4})$/)) ext = matches[1] // include the dot, like .png

        if (filename.length > 128 ) filename = md5(filename) + ext // filename was too long to be backed up, so hash it to shorten it

        // prepend user_id to image so that we know who uploaded it, and so that other users cannot overwrite it
        filename = `${state.current_user.user_id}_${filename}`

        /* todo:
        if (preg_match( '/\.(jpg|jpeg)$/i' , $newname, $matches) && file_exists('/usr/bin/jpegoptim') ) {
            $output = shell_exec("/usr/bin/jpegoptim $newname 2>&1");  // minimize size of new jpeg
        }

        if (preg_match( '/\.(png)$/i' , $newname, $matches) && file_exists('/usr/bin/optipng') ) {
            $output = shell_exec("/usr/bin/optipng $newname 2>&1");  // minimize size of new png
        }
        */

        return filename
    }

    async function comment_mail(c) { // reasons to send out comment emails: @user summons, user watching post

        let p              = await get_row(`select * from posts where post_id=?`, [c.comment_post_id], state)
        let commenter      = c.user_name
        let already_mailed = []
        let offset         = await cid2offset(p.post_id, c.comment_id)

        // if comment_content contains a summons like @user, and user is user_summonable, then email user the comment
        if (matches = c.comment_content.match(/@(\w+)/m)) { // just use the first @user in the comment, not multiple
            let summoned_user_username = matches[1]
            var u
            if (u = await get_row(`select * from users where user_name=? and user_id != ? and user_summonable=1`,
                                       [summoned_user_username, c.comment_author], state)) {

                let subject  = `New ${CONF.domain} comment by ${commenter} directed at ${summoned_user_username}`

                let notify_message  = `<html><body><head><base href="${BASEURL}" ></head>
                New comment by ${commenter} in <a href='${BASEURL}${post2path(p)}'>${p.post_title}</a>:<p>
                <p>${c.comment_content}<p>
                <p><a href='${BASEURL}${post2path(p)}?offset=${offset}#comment-${c.comment_id}'>Reply</a><p>
                <font size='-1'>Stop allowing <a href='${BASEURL}/profile'>@user summons</a></font></body></html>`

                if (u.user_email) mail(u.user_email, subject, notify_message) // user_email could be null in db

                // include in already_mailed so we don't duplicate emails below
                already_mailed[u.user_id] ? already_mailed[u.user_id]++ : already_mailed[u.user_id] = 1
            }
        }

        // commenter logged in right now probably doesn't want to get his own comment in email
        // select all other subscriber user ids and send them the comment by mail
        let sql = `select postview_user_id, postview_post_id from postviews
                        where postview_post_id=? and postview_want_email=1 and postview_user_id != ?
                        group by postview_user_id` // Group by so that user_id is in there only once.

        let rows = []
        if (rows = await query(sql, [c.comment_post_id, c.comment_author], state)) {
            rows.forEach(async function(row) {

                if (already_mailed[row.postview_user_id]) return

                let u = await get_userrow(row.postview_user_id)

                let subject = `New ${CONF.domain} comment in '${p.post_title}'`

                let notify_message  = `<html><body><head><base href="${BASEURL}" ></head>
                New comment by ${commenter} in <a href='${BASEURL}${post2path(p)}'>${p.post_title}</a>:<p>
                <p>${c.comment_content}<p>\r\n\r\n
                <p><a href='${BASEURL}${post2path(p)}?offset=${offset}#comment-${c.comment_id}'>Reply</a><p>
                <font size='-1'>Stop watching <a href='${BASEURL}${post2path(p)}?want_email=0'>${p.post_title}</a></font><br>
                <font size='-1'>Stop watching <a href='${BASEURL}/autowatch?off=true'>all posts</a></font></body></html>`

                mail(u.user_email, subject, notify_message)
                already_mailed[u.user_id] ? already_mailed[u.user_id]++ : already_mailed[u.user_id] = 1
            })
        }
    }

    function format_comment(c) {

        var comment_dislikes = intval(c.comment_dislikes)
        var comment_likes    = intval(c.comment_likes)
        var date_link        = get_permalink(c)
        var del              = get_del_link(c)
        var edit             = get_edit_link(c)
        var nuke             = get_nuke_link(c)
        var icon             = user_icon(c, 0.4, `'align='left' hspace='5' vspace='2'`) // scale image down
        var u                = c.user_name ? `<a href='/user/${c.user_name}'>${c.user_name}</a>` : 'anonymous'
        var clink            = contextual_link(c)

        if (state.current_user) {
            var liketext    = c.commentvote_up   ? 'you like this'    : '&#8593;&nbsp;like';
            var disliketext = c.commentvote_down ? 'you dislike this' : '&#8595;&nbsp;dislike';

            var like    = `<a href='#' id='like_${c.comment_id}' onclick="like('like_${c.comment_id}');return false">${liketext} (${c.comment_likes})</a>`
            var dislike = `<a href='#' id='dislike_${c.comment_id}' onclick="dislike('dislike_${c.comment_id}');return false">${disliketext} (${c.comment_dislikes})</a>`

            if (state.current_user.relationships[c.user_id] &&
                state.current_user.relationships[c.user_id].rel_i_ban) var hide = `style='display: none'`
            else var hide = ''

        }
        else { // not logged in. assume not registered, put link to reg page
            var like    = `<a href='#' onclick="midpage.innerHTML = registerform.innerHTML; return false" >&#8593;&nbsp;like (${comment_likes})</a>`
            var dislike = `<a href='#' onclick="midpage.innerHTML = registerform.innerHTML; return false" >&#8593;&nbsp;dislike (${comment_likes})</a>`
        }

        var offset = intval(_GET('offset'))

        var quote = `<a href="#commentform"
                      onclick="addquote('${c.comment_post_id}', '${offset}', '${c.comment_id}', '${c.user_name}'); return false;"
                      title="select some text then click this to quote" >quote</a>`

        // for the last comment in the whole result set (not just last on this page) add an id="last"
        if (state.comments) { // state.comments may not be defined, for example when we just added one comment
            var last = (c.row_number === state.comments.found_rows) ? `<span id='last'></span>` : ''
        }
        else var last = ''

        c.comment_content = (c.comment_adhom_when && !URL.parse(state.req.url).pathname.match(/jail/)) ?
                    `<a href='/comment_jail#comment-${c.comment_id}'>this comment has been jailed for incivility</a>` : c.comment_content

        return `${last}<div class="comment" id="comment-${c.comment_id}" ${hide} >
        <font size=-1 >
            ${c.row_number || ''}
            ${icon}
            ${u} &nbsp;
            ${date_link} &nbsp;
            ${like} &nbsp;
            ${dislike} &nbsp;
            ${clink} &nbsp;
            ${quote} &nbsp;
            ${edit} &nbsp;
            ${del} &nbsp;
            ${nuke} &nbsp;
        </font><br><span id='comment-${c.comment_id}-text'>${ c.comment_content }</span></div>`
    }

    function comment_box() { // add new comment, just updates page without reload
        return `
        ${state.current_user ? upload_form() : ''}
        <form id='commentform' >
            <textarea id='ta' name='comment_content' class='form-control' rows='10' placeholder='write a comment...' ></textarea><p>
            <input type='hidden' name='comment_post_id' value='${state.post.post_id}' />
            <button class='btn btn-success btn-sm'
                onclick="$.post('/accept_comment?${create_nonce_parms()}', $('#commentform').serialize()).done(function(data) {
                    $('#comment_list').append(data)
                    document.getElementById('commentform').reset() // clear the textbox
                })
                return false" >submit</button>
        </form>`
    }

    function comment_edit_box() { // edit existing comment, redirect back to whole post page

        let comment_id = intval(_GET('c'))

        state.comment.comment_content = newlineify(state.comment.comment_content)

        return `
        <h1>edit comment</h1>
        ${state.current_user ? upload_form() : ''}
        <form id='commentform' action='/accept_edited_comment?${create_nonce_parms()}' method='post' >
            <textarea id='ta' name='comment_content' class='form-control' rows='10' placeholder='write a comment...' >${state.comment.comment_content}</textarea><p>
            <input type='hidden' name='comment_id' value='${comment_id}' />
            <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
        </form>
        <script type="text/javascript">document.getElementById('ta').focus();</script>`
    }

    function comment_list() { // format one page of comments
        let ret = `<div id='comment_list' >`
        ret = ret +
            (state.comments.length ? state.comments.map(item => { return format_comment(item) }).join('') : '<b>no comments found</b>')
        ret = ret + `</div>`
        return ret
    }

    function comment_pagination() { // get pagination links for a single page of comments

        if (!state.comments)                 return
        if (state.comments.found_rows <= 40) return // no pagination links needed if one page or less

        let total    = state.comments.found_rows
        let ret      = `<p id='comments'>`
        let pathname = URL.parse(state.req.url).pathname // "pathNAME" is url path without the ? parms, unlike "path"
        let query    = URL.parse(state.req.url).query

        // offset is mysql offset, ie greatest row number to exclude from the result set
        // offset missing from url -> showing last  40 comments in set (same as total - 40)
        // offset 0                -> showing first 40 comments in set
        // offset n                -> showing first 40 comments after n

        if (!query || !query.match(/offset=\d+/)) { // we are on the last page of comments, ie offset = total - 40
            var offset          = total - 40
            var previous_offset = (total - 80 > 0) ? total - 80 : 0 // second to last page
            var q               = query ? (query + '&') : ''

            var first_link      = `${pathname}?${q}offset=0#comments`
            var previous_link   = `${pathname}?${q}offset=${previous_offset}#comments`
            // there is no next_link because we are necessarily on the last page of comments
            var last_link       = `${pathname}${q ? ('?' + q) : ''}#last` // don't include the question mark unless q
        }
        else { // there is a query string, and it includes offset
            var offset          = intval(_GET('offset'))
            var previous_offset = (offset - 40 > 0) ? offset - 40 : 0
            var next_offset     = (offset + 40 > total - 40) ? total - 40 : offset + 40 // last page will always be 40 comments

            if (offset !== 0) { // don't need these links if we are on the first page
                var first_link    = `${pathname}?${query.replace(/offset=\d+/, 'offset=0')}#comments`
                var previous_link = `${pathname}?${query.replace(/offset=\d+/, 'offset=' + previous_offset)}#comments`
            }

            if (offset < total - 40) { // don't need next link on last page
                var next_link = `${pathname}?${query.replace(/offset=\d+/, 'offset=' + next_offset)}#comments`
            }

            var last_link = `${pathname}?${query.replace(/offset=\d+/, 'offset=' + (total - 40))}#last`
        }

        if (typeof first_link !== 'undefined') {
            ret = ret + `<a href='${first_link}' title='Jump to first comment' >&laquo; First</a> &nbsp; &nbsp;`
        }

        if (typeof previous_link !== 'undefined') {
             ret = ret + `<a href='${previous_link}' title='Previous page of comments' >&laquo; Previous</a> &nbsp; &nbsp; `
        }

        let max_on_this_page = (total > offset + 40) ? offset + 40 : total
        ret = ret + `Comments ${offset + 1} - ${max_on_this_page} of ${total.number_format()} &nbsp; &nbsp; `

        if (typeof next_link !== 'undefined') {
             ret = ret + `<a href='${next_link}' title='Next page of comments' >Next &raquo;</a> &nbsp; &nbsp; `
        }

        return ret + `<a href='${last_link}' title='Jump to last comment' >Last &raquo;</a></br>`
    }

    function comment_search_box() {
        return `<form name='searchform' action='/comments' method='get' > 
          <fieldset> 
          <input type='text'   name='s'      value='' size='17' /> 
          <input type='hidden' name='offset' value='0' /> 
          <input type='submit'               value='Search comments &raquo;' />  
          </fieldset> 
        </form><p>`
    }

    function contextual_link(c) { // a link in the comment header that varies by comment context, jail, moderation, etc

        if (!state.current_user) return ''

        if (URL.parse(state.req.url).pathname.match(/jail/) && (state.current_user.user_level === 4)) {
             return `<a href='/liberate?comment_id=${c.comment_id}' >liberate</a>`
        }
        
        if (URL.parse(state.req.url).pathname.match(/comment_moderation/) && (state.current_user.user_level === 4)) {
            return `<a href='#' onclick="$.get('/approve_comment?comment_id=${ c.comment_id }&${create_nonce_parms()}', function() { $('#comment-${ c.comment_id }').remove() }); return false">approve</a>`
        }

        if (state.current_user.user_pbias >= 3) {
            return (state.current_user.user_id === c.comment_author || state.current_user.user_id === 1) ?
                `<a href='#' onclick="if (confirm('Really mark as uncivil?')) { $.get('/uncivil?c=${ c.comment_id }&${create_nonce_parms()}', function() { $('#comment-${ c.comment_id }').remove() }); return false}" title='attacks person, not point' >uncivil</a>` : ''
        }
    }

    function create_nonce_parms() {
        let ts = Date.now() // current unix time in ms
        let nonce = get_nonce(ts)
        return `ts=${ts}&nonce=${nonce}`
    }

    function die(message) {

        console.log(`died because: ${message}`)

        state.message = message

        let content = html(
            midpage(
                h1()
            )
        )

        send_html(200, content)
    }

    function follow_topic_button(t) { // t is the topic to follow, a \w+ string

        let b = `<button type="button" class="btn btn-default btn-xs" title="get emails of new posts in ${t}" >follow ${t}</button>`

        var unfollow_topic_link = `<span id='unfollow_topic_link' >following<sup>
                             <a href='#' onclick="$.get('/follow_topic?topic=${t}&undo=1&${create_nonce_parms()}&ajax=1',
                             function() { document.getElementById('follow').innerHTML = document.getElementById('follow_topic_link').innerHTML }); return false" >x</a></sup></span>`

        var follow_topic_link = `<span id='follow_topic_link' >
                           <a href='#' title='get emails of new posts in ${t}'
                           onclick="$.get('/follow_topic?topic=${t}&${create_nonce_parms()}&ajax=1',
                           function() { document.getElementById('follow').innerHTML = document.getElementById('unfollow_topic_link').innerHTML }); return false" >${b}</a></span>`

        if (state.current_user
         && state.current_user.topics
         && state.current_user.topics.indexOf(t) !== -1) {
            var follow = `<span id='follow' >${unfollow_topic_link}</span>`
        }
        else {
            var follow = `<span id='follow' >${follow_topic_link}</span>`
        }

        return `<span style='display: none;' > ${follow_topic_link} ${unfollow_topic_link} </span> ${follow}`
    }

    function follow_user_button(u) { // u is the user to follow, a row from users table

        let b = `<button type="button" class="btn btn-default btn-xs" title="get emails of new posts by ${u.user_name}" >follow ${u.user_name}</button>`

        var unfollow_user_link = `<span id='unfollow_user_link' >following<sup>
                             <a href='#' onclick="$.get('/follow_user?other_id=${u.user_id}&undo=1&${create_nonce_parms()}&ajax=1',
                             function() { document.getElementById('follow').innerHTML = document.getElementById('follow_user_link').innerHTML }); return false" >x</a></sup></span>`

        var follow_user_link = `<span id='follow_user_link' >
                           <a href='#' title='hide all posts and comments by ${u.user_name}'
                           onclick="$.get('/follow_user?other_id=${u.user_id}&${create_nonce_parms()}&ajax=1',
                           function() { document.getElementById('follow').innerHTML = document.getElementById('unfollow_user_link').innerHTML }); return false" >${b}</a></span>`

        if (state.current_user
         && state.current_user.relationships
         && state.current_user.relationships[u.user_id]
         && state.current_user.relationships[u.user_id].rel_i_follow) {
            var follow = `<span id='follow' >${unfollow_user_link}</span>`
        }
        else {
            var follow = `<span id='follow' >${follow_user_link}</span>`
        }

        return `<span style='display: none;' > ${follow_user_link} ${unfollow_user_link} </span> ${follow}`
    }

    function footer() {
        return `
        <p id='footer' >
        <center>
        <a href='/users'>users</a> &nbsp;
        <a href='/about'>about</a> &nbsp;
        <a href='/post/1302130/2017-01-28-patnet-improvement-suggestions'>suggestions</a> &nbsp;
        <a href='https://github.com/killelea/node.${CONF.domain}'>source code</a> &nbsp;
        <a href='mailto:${ CONF.admin_email }' >contact</a> &nbsp;
        <br>
        <a href='/topics'>topics</a> &nbsp;
        <a href='/best'>best comments</a> &nbsp;
        <a href='/comment_jail'>comment jail</a> &nbsp;
        <br>
        <a href='/post/1282720/2015-07-11-ten-reasons-it-s-a-terrible-time-to-buy-an-expensive-house'>10 reasons it's a terrible time to buy</a> &nbsp;
        <br>
        <a href='/post/1282721/2015-07-11-eight-groups-who-lie-about-the-housing-market'>8 groups who lie about the housing market</a> &nbsp;
        <br>
        <a href='/post/1282722/2015-07-11-37-bogus-arguments-about-housing'>37 bogus arguments about housing</a> &nbsp;
        <br>
        <a href='/post/1206569/free-bumper-stickers'>get a free bumper sticker:<br><img src='/images/bumpersticker.png' width=300 ></a>
        <br>
        <form method='get' action='/search' ><input name='s' type='text' placeholder='search...' size='20' ></form>
        </center>
        <div class='fixed'>
            <a href='#' title='top of page' >top</a> &nbsp; <a href='#footer' title='bottom of page' >bottom</a> &nbsp; <a href='/' title='home page' >home</a>
        </div>
        <script>
        function like(content) {
            $.get( "/like?comment_id="+content.split("_")[1], function(data) { document.getElementById(content).innerHTML = data; });
        }
        function dislike(content) {
            $.get( "/dislike?comment_id="+content.split("_")[1], function(data) { document.getElementById(content).innerHTML = data; });
        }
        function postlike(content) { // For whole post instead of just one comment.
            $.get( "/like?post_id="+content.split("_")[1], function(data) { document.getElementById(content).innerHTML = data; });
        }
        function postdislike(content) { // For whole post instead of just one comment.
            $.get( "/dislike?post_id="+content.split("_")[1], function(data) { document.getElementById(content).innerHTML = data; });
        }
        </script>`
    }

    function format_date(gmt_date) { // create localized date string from gmt date out of mysql
        var utz = state.current_user ? state.current_user.user_timezone : 'America/Los_Angeles'
        return MOMENT(Date.parse(gmt_date)).tz(utz).format('YYYY MMM D, h:mma')
    }

    function _GET(parm) { // given a string, return the GET parameter by that name
        return URL.parse(state.req.url, true).query[parm]
    }

    async function get_comment_list_by_author(a, start, num) {

        let comments = await query(`select sql_calc_found_rows * from comments left join users on comment_author=user_id
                                    where user_name = ? order by comment_date limit ?, ?`, [a, start, num], state)

        let total = await sql_calc_found_rows()

        return {comments : comments, total : total}
    }

    async function get_comment_list_by_number(n, start, num) {

        let comments = await query(`select sql_calc_found_rows * from comments, users force index (user_comments_index)
                                where comments.comment_author = users.user_id and user_comments = ? order by comment_date desc limit ?, ?`,
                                    [n, start, num], state)

        let total = await sql_calc_found_rows()

        return {comments, total}
    }

    async function get_comment_list_by_search(s, start, num) {

        let comments = await query(`select sql_calc_found_rows * from comments left join users on comment_author=user_id
                                    where match(comment_content) against (?)
                                    order by comment_date desc limit ?, ?`, [s, start, num], state)

        let total = await sql_calc_found_rows()

        return {comments, total}
    }

    function get_del_link(c) {

        if (!state.current_user) return ''

        return (state.current_user.user_id === c.comment_author || state.current_user.user_id === 1) ?
            `<a href='#' onclick="if (confirm('Really delete?')) { $.get('/delete_comment?comment_id=${ c.comment_id }&post_id=${ c.comment_post_id }&${create_nonce_parms()}', function() { $('#comment-${ c.comment_id }').remove() }); return false}">delete</a>` : ''
    }

    function get_edit_link(c) {

        if (!state.current_user) return ''

        if ((state.current_user.user_id === c.comment_author) || (state.current_user.user_level === 4)) {
            return `<a href='/edit_comment?c=${c.comment_id}&${create_nonce_parms()}'>edit</a>`
        }

        return ''
    }

    function get_external_link(post) {

        let c = CHEERIO.load(post.post_content)

        if (!c('a').length) return ''

        let extlink = c('a').attr('href')
        let host = URL.parse(extlink).host

        if (!(['http:', 'https:'].indexOf(URL.parse(extlink).protocol) > -1)) return '' // ignore invalid protocols
        if (new RegExp(CONF.domain).test(host))                               return '' // ignore links back to own domain

        return `<a href='${brandit(extlink)}' target='_blank' title='original story at ${host}' ><img src='/images/ext_link.png'></a>`
    }

    function get_first_image(post) {

        let c = CHEERIO.load(post.post_content)

        if (!c('img').length) return ''

        if (post.post_nsfw)
            return `<div class='icon' ><a href='${post2path(post)}' ><img src='/images/nsfw.png' border=0 width=100 align=top hspace=5 vspace=5 ></a></div>`
        else
            return `<div class='icon' ><a href='${post2path(post)}' ><img src='${c('img').attr('src')}' border=0 width=100 align=top hspace=5 vspace=5 ></a></div>`
    }

    function get_nonce(ts) {
        // create or check a nonce string for input forms. this makes each form usable only once, and only from the ip that got the form.
        // hopefully this slows down spammers and cross-site posting tricks
        return md5(state.ip + CONF.nonce_secret + ts)
    }

    function get_nuke_link(c) {

        if (!state.current_user) return ''

        return (URL.parse(state.req.url).pathname.match(/comment_moderation/) && (state.current_user.user_level === 4)) ?
            `<a href='/nuke?nuke_id=${c.comment_author}&${create_nonce_parms()}' onClick='javascript:return confirm("Really?")' >nuke</a>`
            : ''
    }

    function get_permalink(c) {

        let parm = '' // default is no offset parm, ie last page of comments

        if (_GET('offset') === 0) parm = `?offset=0`
        else if (_GET('offset'))  parm = `?offset=${_GET('offset')}`

        return `<a href='/post/${c.comment_post_id}/${parm}#comment-${c.comment_id}' title='permalink' >${format_date(c.comment_date)}</a>`
    }

    async function get_userrow(user_id) {
        return await get_row('select * from users where user_id = ?', [user_id], state)
    }

    function h1() {
        return `<h1 style='display: inline;' >${ state.message }</h1>`
    }

    function header() {

        var hashtag = ''

        // display hashtag in title if we are on a post in that topic, or in the index for that topic
        if (state.post && state.post.post_topic) hashtag =
            `<a href='/topic/${state.post.post_topic}'><h1 class='sitename' >#${state.post.post_topic}</h1></a>`

        if (state.page === 'topic') {
            var topic = segments(state.req.url)[2] // like /topic/housing
            hashtag = `<a href='/topic/${topic}'><h1 class='sitename' >#${topic}</h1></a>`
        }

        return `<div class='comment' >
            <div style='float:right' >${ icon_or_loginprompt(state) }</div>
            <a href='/' ><h1 class='sitename' title='back to home page' >${ CONF.domain }</h1></a> &nbsp; ${hashtag}
            <br>
            <font size='-1'>${ top_topics() + '<br>' + brag() + '</font><br>' + new_post_button() }
            </div>`
    }

    function html(...args) {

        var queries = state.queries.sortByProp('ms').map( (item) => { return `${ item.ms }ms ${ item.sql }` }).join('\n')

        let title = state.post ? state.post.post_title : CONF.domain

        return `<!DOCTYPE html><html lang="en">
        <head>
        <link href='/${ CONF.stylesheet }' rel='stylesheet' type='text/css' />
        <link rel='icon' href='/favicon.ico' />
        <meta charset='utf-8' />
        <meta name='description' content='${ CONF.description }' />
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no' />
        <title>${ title }</title>
        <script type="text/javascript">

        function addquote(post_id, offset, comment_id, author) {

            var comment_link;
            var textarea = document.forms['commentform'].elements['ta'];
            var theSelection = '';

            if (comment_id > 0)
                comment_link = '<a href="/post/' + post_id + '&offset=' + offset + '#comment-' + comment_id + '">' + author + ' says</a>';
            else
                comment_link = '<a href="/post/' + post_id                                                  + '">' + author + ' says</a>';

            if (theSelection = getHTMLOfSelection()) { // user manually selected something
                if (s = sessionStorage.getItem('tripleclickselect')) { // override tripleclick selection to avoid getting extra html elements
                    theSelection = s.trim(); // trim bc tripleclick appends useless whitespace
                    sessionStorage.removeItem('tripleclickselect'); // so we don't keep using it by mistake
                }
            }
            else { // either we are on mobile (no selection possible) or the user did not select any text
                // whole comment, or post when comment_id === 0
                theSelection = document.getElementById('comment-' + comment_id + '-text').innerHTML;
            }

            if (theSelection.length > 1024) var theSelection = theSelection.substring(0, 1000) + '...'; // might mangle tags

            textarea.value = textarea.value + comment_link + '<br><blockquote>' + theSelection + '</blockquote>';
            textarea.focus();
            return;
        }

        window.addEventListener('click', function (evt) {
            if (evt.detail === 3) {
                sessionStorage.setItem('tripleclickselect', window.getSelection());

                // if they don't use it by clicking "quote" within 10 seconds, delete it so it dn confuse them later
                setTimeout(function() { sessionStorage.removeItem('tripleclickselect'); }, 10000);
            }
        });

        function getHTMLOfSelection () {
          var range;
          if (window.getSelection) {
            var selection = window.getSelection();
            if (selection.rangeCount > 0) {
              range = selection.getRangeAt(0);
              var clonedSelection = range.cloneContents();
              var div = document.createElement('div');
              div.appendChild(clonedSelection);
              return div.innerHTML;
            }
            else {
              return '';
            }
          }
          else {
            return '';
          }
        }

        function on_mobile() { 
            if (navigator.userAgent.match(/Android/i)
             || navigator.userAgent.match(/webOS/i)
             || navigator.userAgent.match(/iPhone/i)
             || navigator.userAgent.match(/iPad/i)
             || navigator.userAgent.match(/iPod/i)
             || navigator.userAgent.match(/BlackBerry/i)
             || navigator.userAgent.match(/Windows Phone/i)
            )    return true;
            else return false;
        }
        </script>
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

    function icon_or_loginprompt() {
        if (state.current_user) return id_box(state)
        else                    return loginprompt(state)
    }

    function id_box() {

        var img = user_icon(state.current_user, 0.4, `'align='left' hspace='5' vspace='2'`) // scale image down

        return `
            <div id='status' >
                ${img}<a href='/user/${state.current_user.user_name}' >${state.current_user.user_name}</a>
            </div>`
    }

    async function ip2country(ip) { // probably a bit slow, so don't overuse this

        if (!ip) return

        ip = ip.replace(/[^0-9\.]/, '')

        return await get_var(`select country_name from countries where inet_aton(?) >= country_start and inet_aton(?) <= country_end`,
                              [ip, ip], state)
    }

    async function login(state, email, password) {

        var user = await get_row('select * from users where user_email = ? and user_pass = ?', [email, md5(password)], state)

        if (!user) {
            state.login_failed_email = email
            state.current_user       = null
            var user_id              = ''
            var user_pass            = ''
        }
        else {
            state.login_failed_email = null
            state.current_user       = user
            var user_id              = state.current_user.user_id
            var user_pass            = state.current_user.user_pass
        }

        if ('post_login' === state.page) var content = icon_or_loginprompt(state)
        if ('key_login'  === state.page) {

            var current_user_id = state.current_user ? state.current_user.user_id : 0

            // left joins to also get each post's viewing and voting data for the current user if there is one
            let sql = `select sql_calc_found_rows * from posts
                       left join postviews on postview_post_id=post_id and postview_user_id= ?
                       left join postvotes on postvote_post_id=post_id and postvote_user_id= ?
                       left join users     on user_id=post_author
                       where post_modified > date_sub(now(), interval 7 day) and post_approved=1
                       order by post_modified desc limit 0, 20`

            state.posts   = await query(sql, [current_user_id, current_user_id], state)
            state.message = `Your password is ${ password } and you are now logged in`

            var content = html(
                midpage(
                    h1()
                )
            )
        }

        var usercookie = `${ CONF.usercookie }=${ user_id   }`
        var pwcookie   = `${ CONF.pwcookie   }=${ user_pass }`
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

        send(200, headers, content)
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

    function maybe(path) { // maybe the object path exists, maybe not
        // we pass in a string, evaluate as an object path, then return the value or null
        // if some object path does not exit, don't just bomb with "TypeError: Cannot read property 'whatever' of null"

        let start = path.split('.')[0]

        try      { return path.split('.').slice(1).reduce((curr, key)=>curr[key], start) }
        catch(e) { return null }
    }

    function midpage(...args) { // just an id so we can easily swap out the middle of the page
        return `<div id="midpage" >
            ${ args.join('') }
            </div>`
    }

    function new_post_button() {
        return '<a href="/new_post" class="btn btn-success btn-sm" title="start a new post" ><b>new post</b></a>'
    }

    function page() { // tell homepage, search, userpage, topic which page we are on

        let curpage = Math.floor(_GET('page')) ? Math.floor(_GET('page')) : 1
        let slimit  = (curpage - 1) * 20 + ', 20' // sql limit for pagination of results.

        let orders = { // maps _GET('order') parm to a posts table column name to order by
            'active'   : 'post_modified',
            'comments' : 'post_comments',
            'likes'    : 'cast(post_likes as signed) - cast(post_dislikes as signed)',
            'new'      : 'post_date',
        }

        let order = orders[_GET('order')] ? _GET('order') : 'active'
        let order_by = 'order by ' + orders[order] + ' desc'

        return [curpage, slimit, order, order_by]
    }

    function popup() {
        return `<script type='text/javascript'> alert('${ state.message }');</script>`
    }

    async function post_mail(p) { // reasons to send out post emails: @user, user following post author, user following post topic

        var already_mailed = []

        // if post_content contains a summons like @user, and user is user_summonable, then email user the post
        if (matches = p.post_content.match(/@(\w+)/m)) { // just use the first @user in the post, not multiple
            var summoned_user_username = matches[1]
            var u
            if (u = await get_row(`select * from users where user_name=? and user_id != ? and user_summonable=1`,
                                       [summoned_user_username, p.post_author], state)) {

                let subject  = `New ${CONF.domain} post by ${p.user_name} directed at ${summoned_user_username}`

                let notify_message  = `<html><body><head><base href="${BASEURL}" ></head>
                New post by ${p.user_name}:  <a href='${BASEURL}${post2path(p)}'>${p.post_title}</a><p>
                <p>${p.post_content}<p>
                <p><a href='${BASEURL}${post2path(p)}'>Reply</a><p>
                <font size='-1'>Stop allowing <a href='${BASEURL}/profile'>@user summons</a></font></body></html>`

                if (u.user_email) mail(u.user_email, subject, notify_message) // user_email could be null in db

                // include in already_mailed so we don't duplicate emails below
                already_mailed[u.user_id] ? already_mailed[u.user_id]++ : already_mailed[u.user_id] = 1
            }
        }

        // now do user follower emails
        var rows = []
        if (rows = await query(`select distinct rel_self_id as user_id from relationships where rel_other_id = ? and rel_i_follow > 0`,
                               [p.post_author], state)) {
            rows.forEach(async function(row) {

                if (already_mailed[row.rel_self_id]) return

                let u = await get_userrow(row.rel_self_id)

                let subject = `New ${CONF.domain} post by ${p.user_name}`

                let notify_message  = `<html><body><head><base href="${BASEURL}" ></head>
                New post by ${p.user_name}, <a href='${BASEURL}${post2path(p)}'>${p.post_title}</a>:<p>
                <p>${p.post_content}<p>\r\n\r\n
                <p><a href='${BASEURL}${post2path(p)}?offset=${offset}#post-${p.post_id}'>Reply</a><p>
                <font size='-1'>Stop following <a href='${BASEURL}/user/${p.user_name}'>${p.user_name}</a></font><br>`

                mail(u.user_email, subject, notify_message)
                already_mailed[u.user_id] ? already_mailed[u.user_id]++ : already_mailed[u.user_id] = 1
            })
        }

        // now do topic follower emails
        if (rows = await query(`select distinct topicwatch_user_id from topicwatches where topicwatch_name = ?`, [p.post_topic], state)) {
            rows.forEach(async function(row) {

                if (already_mailed[row.topicwatch_user_id]) return

                let u = await get_userrow(row.topicwatch_user_id)

                let subject = `New ${CONF.domain} post in ${p.post_topic}`

                let notify_message  = `<html><body><head><base href="${BASEURL}" ></head>
                New post in ${p.post_topic}, <a href='${BASEURL}${post2path(p)}'>${p.post_title}</a>:<p>
                <p>${p.post_content}<p>\r\n\r\n
                <p><a href='${BASEURL}${post2path(p)}?offset=${offset}#post-${p.post_id}'>Reply</a><p>
                <font size='-1'>Stop following <a href='${BASEURL}/topic/${p.post_topic}'>${p.post_topic}</a></font><br>`

                mail(u.user_email, subject, notify_message)
                already_mailed[u.user_id] ? already_mailed[u.user_id]++ : already_mailed[u.user_id] = 1
            })
        }
    }

    function post_pagination(post_count, curpage, extra) {

        let links    = ''
        let nextpage = curpage + 1
        let pages    = Math.floor( (post_count + 20) / 20)
        let path     = URL.parse(state.req.url).pathname
        let prevpage = curpage - 1

        if (curpage > 1) links = links + `<a href='${path}?page=${prevpage}${extra}'>&laquo; previous</a> &nbsp;`

        links = links + ` page ${curpage} of ${pages} `

        if (curpage < pages) links = links + `&nbsp; <a href='${path}?page=${nextpage}${extra}'>next &raquo;</a>`

        return links
    }

    function post() { // format a single post for display

        let uncivil         = ''
        let arrowbox_html = arrowbox(state.post)
        let icon          = user_icon(state.post, 1, `align='left' hspace='5' vspace='2'`)
        let link          = post_link(state.post)
        let nonce_parms   = create_nonce_parms()

        if (state.current_user && state.current_user.user_pbias >= 3) {

            if (!state.post.post_title.match(/thunderdome/)) {
                let confirm_uncivil = `onClick="javascript:return confirm('Really mark as uncivil?')"`
                uncivil = ` &nbsp; <a href='/uncivil?p=${state.post.post_id}&${nonce_parms}' ${confirm_uncivil} title='attacks person, not point' >uncivil</a> &nbsp;` 
            }
        }

        // watch toggle
        var watcheye = `<a href='#' id='watch' onclick="$.get('/watch?post_id=${state.post.post_id}&${nonce_parms}', function(data) {
        document.getElementById('watch').innerHTML = data; });
        return false" title='comments by email'>${watch_indicator(state.post.postview_want_email)}</a>`

        let edit_link = ''
        if (state.current_user && ((state.current_user.user_id === state.post.post_author) || (state.current_user.user_level >= 4)) ) {
            edit_link = `<a href='/edit_post?p=${state.post.post_id}&${nonce_parms}'>edit</a> &nbsp; `
        }

        let delete_link = ''
        if (state.current_user && ((state.current_user.user_id === state.post.post_author && !state.post.post_comments) || (state.current_user.user_level >= 4))) {
            let confirm_del = `onClick="javascript:return confirm('Really delete?')"`
            delete_link = ` &nbsp; <a href='/delete_post?post_id=${state.post.post_id}&${nonce_parms}' ${confirm_del} >delete</a> &nbsp;` 
        }

        return `<div class='comment' >${arrowbox_html} ${icon} <h2 style='display:inline' >${ link }</h2>
                <p>By ${user_link(state.post)} ${follow_user_button(state.post)} &nbsp; ${format_date(state.post.post_date)} ${uncivil}
                ${state.post.post_views.number_format()} views &nbsp; ${state.post.post_comments.number_format()} comments &nbsp;
                ${watcheye} &nbsp;
                <a href="#commentform" onclick="addquote( '${state.post.post_id}', '0', '0', '${state.post.user_name}' ); return false;"
                   title="Select some text then click this to quote" >quote</a> &nbsp;
                &nbsp; ${share_post(state.post)} &nbsp; ${edit_link} ${delete_link}
                <p><div class="entry" class="alt" id="comment-0" >${ state.post.post_content }</div></div>`
    }

    async function post_comment_list(post) {

        let offset = (post.post_comments - 40 > 0) ? post.post_comments - 40 : 0 // If offset is not set, select the 40 most recent comments.

        if (_GET('offset')) offset = intval(_GET('offset')) // But if offset is set, use that instead.

        // if this gets too slow as user_uncivil_comments increases, try a left join, or just start deleting old uncivil comments
        let user_id = state.current_user ? state.current_user.user_id : 0
        let sql = `select sql_calc_found_rows * from comments
                   left join users on comment_author=user_id
                   left join commentvotes on (comment_id = commentvote_comment_id and commentvote_user_id = ?)
                   where comment_post_id = ? and comment_approved = 1
                   order by comment_date limit 40 offset ?`

        let results = await query(sql, [user_id, post.post_id, offset], state)

        // add in the comment row number to the result here for easier pagination info; would be better to do in mysql, but how?
        results = results.map(comment => { comment.row_number = ++offset; return comment })

        return results
    }

    function post_form() { // used both for composing new posts and for editing existing posts; distinction is the presence of p, the post_id

        // todo: add conditional display of user-name chooser for non-logged in users

        if (_GET('p')) {
            var fn = 'edit'
            var title = state.post.post_title.replace(/'/g, '&apos;') // replace to display correctly in single-quoted html value below
            var content = newlineify(state.post.post_content.replace(/'/g, '&apos;'))
            var post_id = `<input type='hidden' name='post_id' value='${state.post.post_id}' />`
        }
        else {
            var fn = 'new post'
            var title = ''
            var content = ''
            var post_id = ''
        }

        return `
        <h1>${fn}</h1>
        <form action='/accept_post' method='post' >
            <div class='form-group'><input name='post_title' type='text' class='form-control' placeholder='title' id='title' value='${title}' ></div>
            <textarea class='form-control' name='post_content' rows='12' id='ta' placeholder='write something...' >${content}</textarea><p>
            ${post_id}
            <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
        </form>
        <script type="text/javascript">document.getElementById('title').focus();</script>
        ${upload_form()}`
    }

    function post_link(post) {
        let path = post2path(post)
        return `<a href='${path}'>${post.post_title}</a>`
    }

    function post_list() { // format a list of posts from whatever source; pass in only a limited number, because all will display

        if (state.posts) {
            var formatted = state.posts.map(post => {

                var link = post_link(post)

                if (!state.current_user && post.post_title.match(/thunderdome/gi)) return '' // hide thunderdome posts if not logged in
                if (!state.current_user && post.post_nsfw)                         return '' // hide porn posts if not logged in

                net = post.post_likes - post.post_dislikes

                if (state.current_user) { // user is logged in
                    if (!post.postview_last_view)
                        var unread = `<a href='${post2path(post)}' ><img src='/content/unread_post.gif' width='45' height='16' title='You never read this one' ></a>`
                    else 
                        var unread = unread_comments_icon(post, post.postview_last_view) // last view by this user, from left join
                }
                else var unread = ''

                let ago           = MOMENT(post.post_modified).fromNow();
                let hashlink      = `in <a href='/topic/${post.post_topic}'>#${post.post_topic}</a>`
                let imgdiv        = (state.current_user && state.current_user.user_hide_post_list_photos) ? '' : get_first_image(post)
                let arrowbox_html = arrowbox(post)
                let extlink       = get_external_link(post)
                let firstwords    = `<font size='-1'>${first_words(post.post_content, 30)}</font>`

                if (URL.parse(state.req.url).pathname.match(/post_moderation/) && (state.current_user.user_level === 4)) {
                    var approval_link = `<a href='#' onclick="$.get('/approve_post?post_id=${ post.post_id }&${create_nonce_parms()}', function() { $('#post-${ post.post_id }').remove() }); return false">approve</a>`
                }
                else var approval_link = ''

                if (post.post_comments) {
                    let s = (post.post_comments === 1) ? '' : 's';
                    let path = post2path(post)
                    // should add commas to post_comments here
                    var latest = `<a href='${path}'>${post.post_comments}&nbsp;comment${s}</a>, latest <a href='${path}#comment-${post.post_latest_comment_id}' >${ago}</a>`
                }
                else var latest = `Posted ${ago}`

                if (state.current_user                                 &&
                    state.current_user.relationships[post.post_author] &&
                    state.current_user.relationships[post.post_author].rel_i_ban) var hide = `style='display: none'`
                else var hide = ''

                return `<div class='post' id='post-${post.post_id}' ${hide} >${arrowbox_html}${imgdiv}<b><font size='+1'>${link}</font></b>
                       ${extlink}<br>by <a href='/user/${ post.user_name }'>${ post.user_name }</a> ${hashlink} &nbsp;
                       ${latest} ${unread} ${approval_link} <br>${firstwords}</div>`
            })
        }
        else formatted = []

        return formatted.join('')
    }

    function post2path(post) {
        let slug = slugify(`${post.post_title}`)
        return `/post/${post.post_id}/${slug}`
    }

    function profile_form() {

        if (!state.current_user) return die('please log in to edit your profile')

        let u = state.current_user

        let ret = '<h1>edit profile</h1>'

        if (_GET('updated')) ret += `<h3><font color='green'>your profile has been updated</font></h3>`

        ret += `
        <table>
        <tr>
        <td>${user_icon(u)} &nbsp; </td>
        <td>
            <div style='margin: 0px; padding: 5px; border: 1px solid #ddd; background-color: #f5f5f5; display: inline-block;' >
                <form enctype='multipart/form-data' id='upload-file' method='post' action='upload'>
                    Upload any size image to represent you (gif, jpg, png, bmp)<br>
                    Image will automatically be resized after upload<p>
                    <input type='file'   id='upload' name='image' class='form' />
                    <input type='submit' value='Upload &raquo;' class='form' />
                </form>
            </div>
        </td>
        </tr>
        </table>
        <p>
        <form name='profile' action='update_profile?${create_nonce_parms()}' method='post'>
        <input type='text' name='user_name'  placeholder='user_name' size='25' value='${ u.user_name }'  maxlength='30'  /> user name<p>
        <input type='text' name='user_email' placeholder='email'     size='25' value='${ u.user_email }' maxlength='100' /> email<p>
        <br>
        <input type='checkbox' name='user_summonable' value='1' ${ u.user_summonable ? 'checked' : '' } >
            Get emails of comments which have '@${ u.user_name }' and get emails of 'likes' of your comments
        <br>
        <input type='checkbox' name='user_hide_post_list_photos' value='1' ${ u.user_hide_post_list_photos ? 'checked' : '' } >
            Hide images on post lists
        <h2>about you</h2>
        <textarea class='form-control' rows='3' name='user_aboutyou' >${u.user_aboutyou}</textarea><br>

        <input type='submit' class='btn btn-success btn-sm' value='Save' />
        </form><p><h3>ignored users</h3>(click to unignore that user)<br>`

        let ignored_users = state.current_user.relationships.filter(rel => rel.rel_i_ban)
        
        if (ignored_users.length)
            ret += ignored_users.map(u => `<a href='#' onclick="$.get('/ignore?other_id=${u.user_id}&undo=1&${create_nonce_parms()}',
             function() { $('#user-${ u.user_id }').remove() }); return false" id='user-${u.user_id}' >${u.user_name}</a><br>`).join('')
        else
            ret += 'none'

        return ret
    }

    function redirect(redirect_to, code=303) {

        var message = `Redirecting to ${ redirect_to }`

        var headers =  {
          'Location'       : redirect_to,
          'Content-Length' : message.length,
          'Expires'        : new Date().toUTCString()
        }

        send(code, headers, message)
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

    async function reset_latest_comment(post_id) { // reset post table data about latest comment, esp post_modified time

        if (!post_id) return

        let comment_row = await get_row(`select * from comments where comment_post_id=? and comment_approved > 0
                                         order by comment_date desc limit 1`, [post_id], state) 

        if (comment_row) { // this is at least one comment on this post
            let post_comments = await get_var(`select count(*) as c from comments where comment_post_id=? and comment_approved=1`,
                                              [post_id], state)

            let firstwords = first_words(comment_row.comment_content, 40)

            await query(`update posts set
                         post_modified=?,
                         post_comments=?,
                         post_latest_comment_id=?,
                         post_latest_commenter_id=?,
                         post_latest_comment_excerpt=?
                         where post_id=?`,
                         [comment_row.comment_date,
                          post_comments,
                          comment_row.comment_id,
                          comment_row.comment_author,
                          firstwords,
                          post_id], state) // post_modified is necessary for sorting posts by latest comment
        }
        else { // there are no comments
            await query(`update posts set
                         post_modified=post_date,
                         post_comments=0,
                         post_latest_comment_id=0,
                         post_latest_commenter_id=0,
                         post_latest_comment_excerpt=''
                         where post_id=?`, [post_id], state)
        }
    }

    function send(code, headers, content) {
        state.res.writeHead(code, headers)
        state.res.end(content)
        if (state.db) try { state.db.release() }
                      catch (e) { console.log(`${e.message} when releasing ${state.db.threadId} for ${state.req.url}`) }
    }

    function send_html(code, html) {

        //html = html.replace(/\/\/.*/, ' ') // remove js comments
        //html = html.replace(/\s+/g, ' ')   // primitive compression. requires that browser js statements end in semicolon!

        var headers =    {
            'Content-Type'   : 'text/html',
            'Content-Length' : html.length,
            'Expires'        : new Date().toUTCString()
        }

        send(code, headers, html)
    }

    async function send_login_link(state) {

        let post_data = await collect_post_data_and_trim(state)

        if (!valid_email(post_data.user_email)) return `Please go back and enter a valid email`

        let key      = get_nonce(Date.now())
        let key_link = `${BASEURL}/key_login?key=${ key }`

        var results = await query('update users set user_activation_key=? where user_email=?', [key, post_data.user_email], state)

        if (results.changedRows) {

            let message = `Click here to log in and get your password: <a href='${ key_link }'>${ key_link }</a>`

            mail(post_data.user_email, `Your ${ CONF.domain } login info`, message)

            return `Please check your ${post_data.user_email} email for the login link`
        }
        else return `Could not find user with email ${ post_data.user_email }`
    }

    function share_post(post) {
        let share_title = encodeURI(post.post_title).replace(/%20/g,' ')
        share_link  = encodeURI('https://' + CONF.domain +  post2path(post) )
        return `<a href='mailto:?subject=${share_title}&body=${share_link}' title='email this' >share
                <img src='/images/mailicon.jpg' width=15 height=12 ></a>`
    }

    function slugify(s) { // url-safe pretty chars only; not used for navigation, only for seo and humans
        return s.replace(/\W+/g,'-').toLowerCase().replace(/-+/,'-').replace(/^-+|-+$/,'')
    }

    async function sql_calc_found_rows() {
        return await get_var('select found_rows() as f', [], state)
    }

    function tabs(order, extra='') {

        let selected_tab = []
        selected_tab['active']   = ''
        selected_tab['comments'] = ''
        selected_tab['likes']    = ''
        selected_tab['new']      = ''
        selected_tab[order]      = `class='active'` // default is active

        let path = URL.parse(state.req.url).pathname // "pathNAME" is url path without ? parms, unlike "path"

        return `<ul class='nav nav-tabs'>
            <li ${selected_tab['active']}   > <a href='${path}?order=active${extra}'   title='most recent comments'       >active</a></li>
            <li ${selected_tab['comments']} > <a href='${path}?order=comments${extra}' title='most comments in last week' >comments</a></li>
            <li ${selected_tab['likes']}    > <a href='${path}?order=likes${extra}'    title='most likes in last week'    >likes</a></li>
            <li ${selected_tab['new']}      > <a href='${path}?order=new${extra}'      title='newest'                     >new</a></li>
            </ul>`
    }

    function text() {
        return `${ state.text || '' }`
    }

    function top_topics() { // try just statically coding these to save 26ms on each hit
        //var formatted = state.header_data.top3.map(item => `<a href='/topic/${ item.post_topic }'>#${ item.post_topic }</a>`)
        //return formatted.join(' ') + ` <a href='/random'>#random</a> <a href='/topics/'>more&raquo;</a>`
        return `
            <a href='/topic/housing'>#housing</a> 
            <a href='/topic/investing'>#investing</a> 
            <a href='/topic/politics'>#politics</a> 
            <a href='/random'>#random</a> <a href='/topics/'>more&raquo;</a>`
    }

    function topic_list() {
        if (state.topics) {
            var formatted = state.topics.map( (item) => {
                return `<a href='/topic/${ item.post_topic }'>#${ item.post_topic }</a>`
            })

            return formatted.join(' ')
        }
    }

    function topic_nav() {
        let prev_link = state.post.prev ? `&laquo; <a href='/post/${state.post.prev}'>prev</a>  &nbsp;` : ''
        let next_link = state.post.next ? `&nbsp;  <a href='/post/${state.post.next}'>next</a> &raquo;` : ''

        return `<b>${prev_link} ${next_link}</b>`
    }

    function unread_comments_icon(post, last_view) { // return the blinky icon if there are unread comments in a post

        // if post.post_latest_commenter_id is an ignored user, just return
        // prevents user from seeing blinky for ignored users, but unfortunately also prevents blinky for wanted unread comments before that
        if (state.current_user
         && state.current_user.relationships
         && state.current_user.relationships[post.post_latest_commenter_id]
         && state.current_user.relationships[post.post_latest_commenter_id].rel_i_ban) { return '' }

        // if post_modified > last time they viewed this post, then give them a link to earliest unread comment
        let last_viewed = Date.parse(last_view) / 1000
        let modified    = Date.parse(post.post_modified) / 1000

        if (modified > last_viewed) {

            let unread = `<a href='/since?p=${post.post_id}&when=${last_viewed}' ><img src='/content/unread_comments.gif' width='19' height='18' title='View unread comments'></a>`

            return unread
        }
        else return ''
    }

    function upload_form() {

        return `
        <form enctype='multipart/form-data' id='upload-file' method='post' target='upload_target' action='/upload' >
            <input type='file'   id='upload'   name='image' class='form' /> 
            <input type='submit' value='Include Image' class='form' />
        </form>
        <iframe id='upload_target' name='upload_target' src='' style='display: none;' ></iframe>` // for uploading a bit of js to insert the img link
    }

    function user_icon(u, scale=1, img_parms='') { // clickable icon for this user if they have icon

        user_icon_width  = Math.round(u.user_icon_width  * scale)
        user_icon_height = Math.round(u.user_icon_height * scale)

        return u.user_icon ?
                `<a href='/user/${ u.user_name }'><img src='${u.user_icon}' width='${user_icon_width}' height='${user_icon_height}' ${img_parms} ></a>`
                : ''
    }

    function user_info(u) {
        let img = user_icon(u)

        if (state.current_user && u.user_id === state.current_user.user_id) {
            var edit_or_logout = `<div style='float:right'>
            <b><a href='/edit_profile'>edit profile</a> &nbsp; 
               <a href='#' onclick="$.get('/logout', function(data) { $('#status').html(data) });return false">logout</a></b><p>
            </div><div style='clear: both;'></div>`
        }
        else var edit_or_logout = ''

        let offset = (u.user_comments - 40 > 0) ? u.user_comments - 40 : 0

        var unignore_link = `<span id='unignore_link' >ignoring ${u.user_name}<sup>
                             <a href='#' onclick="$.get('/ignore?other_id=${u.user_id}&undo=1&${create_nonce_parms()}',
                             function() { document.getElementById('ignore').innerHTML = document.getElementById('ignore_link').innerHTML }); return false" >x</a></sup></span>`

        var ignore_link = `<span id='ignore_link' >
                           <a href='#' title='hide all posts and comments by ${u.user_name}'
                           onclick="$.get('/ignore?other_id=${u.user_id}&${create_nonce_parms()}',
                           function() { document.getElementById('ignore').innerHTML = document.getElementById('unignore_link').innerHTML }); return false" >ignore</a></span>`

        if (state.current_user
         && state.current_user.relationships
         && state.current_user.relationships[u.user_id]
         && state.current_user.relationships[u.user_id].rel_i_ban) {
            var ignore = `<span id='ignore' >${unignore_link}</span>`
        }
        else {
            var ignore = `<span id='ignore' >${ignore_link}</span>`
        }

        return `${edit_or_logout}
                <center>
                <a href='/user/${u.user_name}' >${ img }</a><h2>${u.user_name}</h2>
                ${u.user_aboutyou ? u.user_aboutyou : ''}
                <p>joined ${ format_date(u.user_registered) } &nbsp;
                ${u.user_country ? u.user_country : ''}
                ${u.user_posts.number_format()} posts &nbsp;
                <a href='/comments?a=${encodeURI(u.user_name)}&offset=${offset}'>${ u.user_comments.number_format() } comments</a> &nbsp;
                ${follow_user_button(u)} &nbsp;
                <span style='display: none;' > ${ignore_link} ${unignore_link} </span>
                ${ignore}
                </center>`
    }

    function user_link(u) {
        return `<a href='/user/${ u.user_name }'>${ u.user_name }</a>`
    }

    function user_list() {

        let d = _GET('d') ? _GET('d').replace(/[^adesc]/, '').substring(0,4)  : 'desc' // asc or desc
        let i = (d === 'desc') ? 'asc' : 'desc'                                         // invert asc or desc

        let header = `
        <form name='input' action='/users' method='get' >
        <input type='text' size=40 maxlength=80 name='user_name' autofocus />
        <input type='submit' value='User Search' />
        </form><p>
        <table width='100%' cellpadding='10' style="overflow-x:auto;" ><tr>
        <th ></th>
        <th                    ><a href='/users?ob=user_name&d=${ i }'       title='order by user name' >Username</a></th>
        <th                    ><a href='/users?ob=user_registered&d=${ i }' title='order by registration date' >Registered</a></th>
        <th class='text-right' ><a href='/users?ob=user_posts&d=${ i }'      title='order by number of posts started' >Posts</a></th>
        <th class='text-right' ><a href='/users?ob=user_comments&d=${ i }'   title='order by number of comments' >Comments</a></th>
        <th class='text-right' ><a href='/users?ob=user_likes&d=${ i }'      title='number of likes user got' >Likes</a></th>
        <th class='text-right' ><a href='/users?ob=user_dislikes&d=${ i }'   title='number of dislikes user got' >Dislikes</a></th>
        <th class='text-right' ><a href='/users?ob=user_friends&d=${ i }'    title='order by number of friends' >Friends</a></th>
        <th class='text-right' ><a href='/users?ob=user_followers&d=${ i }'  title='order by number of followers' >Followers</a></th>
        <th class='text-right' ><a href='/users?ob=user_bannedby&d=${ i }'   title='how many people are ignoring user' >Ignored By</a></th>
        <th class='text-right' ><a href='/users?ob=user_banning&d=${ i }'    title='how many people user is ignoring' >Ignoring</a></th>
        </tr>`

        if (state.users.length) {
            formatted = state.users.map( (u) => {
                return `<tr id='this_user' >
                    <td >${user_icon(u)}</td>
                    <td align=left >${user_link(u)}</td>
                    <td align=left >${format_date(u.user_registered)}</td>
                    <td align=right ><a href='/user/${u.user_name}' >${u.user_posts.number_format()}</a></td>
                    <td align=right ><a href='/comments?a=${u.user_name}'>${u.user_comments.number_format()}</a></td>
                    <td align=right >${u.user_likes.number_format()}</td>
                    <td align=right >${u.user_dislikes.number_format()}</td>
                    <td align=right ><a href='/users?friendsof=${u.user_id}' >${u.user_friends.number_format()}</a></td>
                    <td align=right ><a href='/users?followersof=${u.user_id}' >${u.user_followers.number_format()}</a></td>
                    <td align=right >${u.user_bannedby.number_format()}</td>
                    <td align=right >${u.user_banning.number_format()}</td>
                   </tr>`
            })

            var result = formatted.join('')
        }
        else var result = 'no such user'

        return header + result + '</table>'
    }

    function valid_nonce() {

        if (intval(_GET('ts')) < (Date.now() - 7200000)) return false // don't accept timestamps older than two hours

        if (get_nonce(_GET('ts')) === _GET('nonce')) return true
        else                                         return false
    }

    function invalid_nonce_message() {
        return `invalid nonce: ${_GET('nonce')} !== ${get_nonce(_GET('ts'))} with ts=${_GET('ts')} and now=${Date.now()}`
    }

    function watch_indicator(want_email) {
        return want_email ? `<img src='/content/openeye.png'> unwatch` : `<img src='/content/closedeye.png'> watch`
    }

    // end of render() functions

    if (typeof pages[state.page] === 'function') { // hit the db iff the request is for a valid url
        try {
            await get_connection_from_pool(state)
            await block_countries(state)
            await block_nuked(state)
            await set_user(state)
            await header_data(state)
            await pages[state.page](state)
        }
        catch(e) {
            console.log(`${Date()} ${state.req.url} FAILED with headers ${JSON.stringify(state.req.headers)}`)
            return send_html(500, `node server error: ${e}`)
        }
    }
    else return send_html(404, `404: ${state.page} was not found`)

} // end of render()
