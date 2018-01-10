// copyright 2017 by Patrick Killelea under the GPLv2 license

'use strict'

// globals are capitalized
const CHEERIO     = require('cheerio')         // via npm to parse html
const CLUSTER     = require('cluster')
const CONF        = require('./_conf.json')    // _conf.json is required
const CRYPTO      = require('crypto')
const FORMIDABLE  = require('formidable')      // via npm for image uploading
const FS          = require('fs')
const HTTP        = require('http')
const JSDOM       = require('jsdom').JSDOM
const LOCKS       = {}                         // db locks to allow only one db connection per ip; helps mitigate dos attacks
const MOMENT      = require('moment-timezone') // via npm for time parsing
const MYSQL       = require('mysql')           // via npm to interface to mysql
const NODEMAILER  = require('nodemailer')      // via npm to send emails
const OS          = require('os')
const QUERYSTRING = require('querystring')
const URL         = require('url')

// following are dependent on requires above
const BASEURL     = ('dev' === process.env.environment) ? CONF.baseurl_dev : CONF.baseurl // CONF.baseurl_dev is for testing
const POOL        = MYSQL.createPool(CONF.db)

const permissions = {}
const routes      = {}
routes.GET        = {}
routes.POST       = {}

process.on('unhandledRejection', (reason, p) => { // very valuable for debugging unhandled promise rejections
    console.error('Unhandled Rejection at promise:', p, 'reason:', reason)
    console.error(reason.stack)
})

process.on('uncaughtException', function (error) {
    console.error(error)
})

if (CLUSTER.isMaster && !('dev' === process.env.environment)) { // to keep debugging simpler, do not fork in dev
    for (var i = 0; i < OS.cpus().length; i++) CLUSTER.fork()

    CLUSTER.on('exit', function(worker, code, signal) {
        console.error(`worker pid ${worker.process.pid} died with code ${code} from signal ${signal}, replacing that worker`)
        CLUSTER.fork()
    })
} else HTTP.createServer(render).listen(CONF.http_port)

async function render(req, res) {

    res.start_time = Date.now()

    const ip   = req.headers['x-forwarded-for']
    const page = segments(req.url)[1] || 'home'

    const context = { ip, page, req, res }

    if (!routes[req.method] || typeof routes[req.method][page] !== 'function')
        return send(404, {'Content-Type' : 'text/html;charset=utf-8'}, `${page} was not found`, { res: res, db: null, ip : ip})

    context.db = await get_connection_from_pool(ip).catch(e => send(429, {'Content-Type' : 'text/html;charset=utf-8'}, e, context))

    if (!context.db)                                   return send_html(500, 'failed to get db connection from pool', context)
    if (await blocked(context.db, context.ip))         return send_html(403, 'ip address blocked', context)
    if (await block_countries(context.db, context.ip)) return send_html(403, 'permission denied to evil country', context)

    context.current_user = await get_user(context)
    context.header_data  = await header_data(context)

    try {
        await routes[req.method][page](context) // eg routes.GET.home
    }
    catch(e) {
        var message = e.message || e.toString()
        console.error(`${Date()} ${context.ip} ${context.req.url} failed with: ${message} ${e.stack || ''}`)
        return send_html(intval(e.code) || 500, `node server says: ${message}`, context)
    }
}

function send(code, headers, content, context) {
    context.res.writeHead(code, headers)
    context.res.end(content)
    release_connection_to_pool(context.db, context.ip)
}

function send_html(code, html, context) {

    //html = html.replace(/\/\/.*/, ' ') // remove js comments
    //html = html.replace(/\s+/g, ' ')   // primitive compression. requires that browser js statements end in semicolon!

    var headers =    {
        'Content-Type'   : 'text/html;charset=utf-8',
        'Expires'        : new Date().toUTCString()
    }

    send(code, headers, html, context)
}

function send_json(code, obj, context) {

    var headers =    {
        'Content-Type'   : 'text/html;charset=utf-8',
        'Expires'        : new Date().toUTCString()
    }

    send(code, headers, JSON.stringify(obj), context)
}

function get_connection_from_pool(ip) {

    return new Promise(function(resolve, reject) {

        if (LOCKS[ip]) return reject('rate limit exceeded')

        LOCKS[ip] = Date.now() // set a database lock for this ip; each ip is allowed only one outstanding connection at a time

        POOL.getConnection(function(err, db) {
            if (err) {
                console.trace()
                reject(err)
            }
            else {
                db.queries = []
                setTimeout((db, ip) => { release_connection_to_pool(db, ip) }, 2000) // don't let lock last for more than two seconds
                resolve(db)
            }
        })
    })
}

function release_connection_to_pool(db, ip) {
    if (db) db.release()
    delete LOCKS[ip]
}

async function block_countries(db, ip) { // block entire countries like Russia because all comments from there are inevitably spam
    return await get_var('select country_evil from countries where inet_aton(?) >= country_start and inet_aton(?) <= country_end',
        [ip, ip], db) ? true : false
}

async function is_foreign(context) {

    var country_name = await get_var(`select country_name from countries where inet_aton(?) >= country_start and inet_aton(?) <= country_end`,
                                     [context.ip, context.ip], context.db)

    if (country_name !== 'United States') return true
    else                                  return false
}

async function blocked(db, ip) { // was the ip nuked in the past?
    return (await get_var('select count(*) as c from nukes where nuke_ip = ?', [ip], db)) ? true : false
}

async function header_data(context) { // data that the page header needs to render
    return {
        comments : await get_var(`select count(*) as c from comments`,           null, context.db), // int
        lurkers  : await get_var(`select count(*) from lurkers`,                 null, context.db), // int
        onlines  : await query(`select * from onlines order by online_username`, null, context.db), // obj
        tot      : await get_var(`select count(*) as c from users`,              null, context.db), // int
    }
}

function collect_post_data(context) { // if there is any POST data, accumulate it and return it in resolve()

    return new Promise(function(resolve, reject) {

        if (context.req.method === 'POST') {
            var body = ''

            context.req.on('data', function (data) {
                body += data

                if (body.length > 1e6) { // too much POST data, kill the connection
                    context.req.connection.destroy()
                    throw { code : 413, message : 'Too much POST data', }
                }
            })

            context.req.on('end', function () {
                resolve(QUERYSTRING.parse(body))
            })
        }
        else {
            console.trace()
            reject(`attempt to collect_post_data from non-POST by ${context.ip}`)
        }
    })
}

async function collect_post_data_and_trim(context) { // to deal with safari on iphone tacking on unwanted whitespace to post form data

    let post_data = await collect_post_data(context)
    Object.keys(post_data).forEach(key => { post_data[key] = post_data[key].trim() })
    delete post_data.submit // because some browsers include submit as a data field

    return post_data
}

async function get_user(context) { // update context with whether they are logged in or not

    try {
        var pairs = []

        context.req.headers.cookie.replace(/\s/g,'').split(';').forEach(function(element) {
            var name  = element.split('=')[0]
            var value = element.split('=')[1]
            pairs[name] = value
        })

        let current_user = await get_row('select * from users where user_id = ? and user_pass = ?',
            [pairs[CONF.usercookie], pairs[CONF.pwcookie]], context.db)

        if (current_user && current_user.user_id) {
            current_user.is_moderator_of = (await query('select topic from topics where topic_moderator = ?',
                                                        [current_user.user_id], context.db)).map(row => row.topic)
            current_user = await set_relations(current_user, context)
            current_user = await set_topics(current_user, context)

            // update users currently online for display in header
            await query(`delete from onlines where online_last_view < date_sub(now(), interval 5 minute)`, null, context.db)
            await query(`insert into onlines (online_user_id, online_username, online_last_view) values (?, ?, now())
                         on duplicate key update online_last_view=now()`, [current_user.user_id, current_user.user_name], context.db)
        }

        return current_user
    }
    catch(e) { // no valid cookie
        if (context.req.headers['user-agent'] &&
            context.req.headers['user-agent'].match(/bot/m)) return null

        // if user-agent does not have 'bot' in it, then count it as a lurker
        await query(`delete from lurkers where lurker_last_view < date_sub(now(), interval 5 minute)`, null, context.db)
        await query(`insert into lurkers (lurker_username, lurker_last_view) values (?, now())
                     on duplicate key update lurker_last_view=now()`, [ip2anon(context.ip)], context.db)
        return null
    }
}

async function set_relations(current_user, context) { // update current_user with his relationships to other users
    // todo: eventually cache this data so we don't do the query on each hit
    if (current_user) {
        let copy = JSON.parse(JSON.stringify(current_user)) // we never modify our parameters

        let non_trivial = `rel_my_friend > 0 or rel_i_ban > 0 or rel_i_follow > 0`
        let my_pov      = `select * from relationships
                           left join users on users.user_id=relationships.rel_other_id where rel_self_id = ? and (${non_trivial})`

        let results = await query(my_pov, [copy.user_id], context.db)

        copy.relationships = [] // now renumber results array using user_ids to make later access easy

        for (var i = 0; i < results.length; ++i) copy.relationships[results[i].rel_other_id] = results[i]

        return copy
    }
}

async function set_topics(current_user, context) { // update current_user object with topics he follows
    if (current_user) {
        let copy = JSON.parse(JSON.stringify(current_user)) // we never modify our parameters
        var results = await query(`select topicwatch_name from topicwatches where topicwatch_user_id=?`, [copy.user_id], context.db)
        copy.topics = results.map(row => row.topicwatch_name)

        return copy
    }
}

function md5(str) {
    var hash = CRYPTO.createHash('md5')
    hash.update(str)
    return hash.digest('hex')
}

function ip2anon(ip) {
    return 'anon_' + md5(ip).substring(0, 5)
}

function intval(s) { // return integer from a string or float
    return parseInt(s) ? parseInt(s) : 0
}

function valid_email(e) {
    return /^\w.*@.+\.\w+$/.test(e)
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
        if (error) console.error('error in mail: ' + error + info)
    })
}

Number.prototype.number_format = function() {
    return this.toLocaleString('en')
}

String.prototype.linkify = function() {

    let blockquotePattern = /""(.+?)""/gim
    let boldPattern       = / \*(.+?)\*/gim
    let emailpostPattern  = /([\w.]+@[a-zA-Z_-]+?(?:\.[a-zA-Z]{2,6})+)\b(?!["<])/gim
    let imagePattern      = /((https?:\/\/[\w$%&~\/.\-;:=,?@\[\]+]*?)\.(jpg|jpeg|gif|gifv|png|bmp))(\s|$)/gim
    let ipadPattern       = /Sent from my iPad/gim
    let italicPattern     = / _(.+?)_/gim
    let linebreakPattern  = /\n/gim
    let pseudoUrlPattern  = /(^|[^\/])(www\.[\S]+(\b|$))(\s|$)/gim                                    // www. sans http:// or https://
    let urlPattern        = /\b(https?:\/\/[a-z0-9-+&@#\/%?=~_|!:,.;]*[a-z0-9-+&@#\/%=~_|])(\s|$)/gim // http://, https://
    let vimeoPattern      = /(?:^|\s)[a-zA-Z\/\/:\.]*(player.)?vimeo.com\/(video\/)?([a-zA-Z0-9]+)/i
    let youtubePattern    = /(?:^|\s)[a-zA-Z\/\/:\.]*youtu(be.com\/watch\?v=|.be\/|be.com\/v\/|be.com\/embed\/)([a-zA-Z0-9\-_]+)([a-zA-Z0-9\/\*\-\_\?\&\;\%\=\.]*)/i

    let result = this
        .trim()
        .replace(/\r/gim,          '')
        .replace(ipadPattern,      '')
        .replace(vimeoPattern,     '<iframe src="//player.vimeo.com/video/$3" width="500" height="375" frameborder="0" webkitallowfullscreen mozallowfullscreen allowfullscreen></iframe>')
        .replace(youtubePattern,   '<iframe width="500" height="375" src="//www.youtube.com/embed/$2$3" allowfullscreen></iframe>')
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

    const allowed = { // with allowed attributes as an array
        'a'          : ['href', 'title', 'rel', 'rev', 'name'],
        'b'          : [],
        'blockquote' : [],
        'br'         : [],
        'font'       : ['color', 'face'],
        'i'          : [],
        'iframe'     : ['src', 'height', 'width'],
        'img'        : ['alt', 'align', 'border', 'height', 'hspace', 'longdesc', 'vspace', 'src', 'width'],
        'li'         : [],
        'ol'         : [],
        'p'          : [],
        'strike'     : [],
        'u'          : [],
        'ul'         : [],
        'video'      : ['width', 'height', 'name', 'src', 'controls'],
        'vsmall'     : [],
    }

    const dom = new JSDOM(s)

    var tag
    for (tag in allowed) {
        let selection = dom.window.document.getElementsByTagName(tag)

        for (var i=0; i < selection.length; i++) {
            var item = selection[i]

            if (item.hasAttributes()) {
                for(var j = 0; j < item.attributes.length; j++) {
                    if (allowed[tag].indexOf(item.attributes[j].name) === -1) {
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

    var matches
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

        var matches
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

async function get_row(sql, sql_parms, db) {
    let results = await query(sql, sql_parms, db)
    return results.length ? results[0] : null
}

async function get_var(sql, sql_parms, db) {
    let results = await query(sql, sql_parms, db)
    
    if (results.length) {
        let firstkey = Object.keys(results[0])
        return results[0][firstkey]
    }
    else return null
}

async function sql_calc_found_rows(db) {
    return await get_var('select found_rows() as f', [], db)
}

function query(sql, sql_parms, db, debug) {

    return new Promise(function(resolve, reject) {
        var query

        if (!db) {
            console.trace()
            return reject('attempt to use db without connection')
        }

        var get_results = async function (error, results, fields, timing) { // callback to give to db.query()

            if (debug) console.log(query.sql)

            if (error) {
                console.error('db error when attempting to run: ' + query.sql)
                console.trace()
                return reject(error)
            }

            db.queries.push({ // for logging within the html footer
                sql : query.sql,
                ms  : timing
            })

            if (query.sql.match(/sql_calc_found_rows/)) results.found_rows = await sql_calc_found_rows(db)

            return resolve(results)
        }

        query = sql_parms ? db.query(sql, sql_parms, get_results)
                          : db.query(sql,            get_results)
    })
}

Array.prototype.sortByProp = function(p){
    return this.sort(function(a,b){
        return (a[p] > b[p]) ? 1 : (a[p] < b[p]) ? -1 : 0
    })
}

function segments(path) { // return url path split up as array of cleaned \w strings

    if (!path) return

    return URL.parse(path).path.replace(/\?.*/,'').split('/').map(segment => segment.replace(/[^\w%]/g,''))
}

function getimagesize(file) {
    return new Promise(function(resolve, reject) {
        if (FS.existsSync(file)) {

            let { spawn } = require('child_process')
            let identify  = spawn('identify', ['-format', '%w %h', file]) // identify -format '%w %h' file

            identify.stdout.on('data', data => {
                let dims = data.toString('utf8').replace(/\n/,'').split(' ') // data is returned as string like '600 328\n'
                resolve([dims[0], dims[1]]) // width and height
            })

            identify.stderr.on('data', data => { // remove the file because something is wrong with it
                if (FS.existsSync(file)) FS.unlinkSync(file)
                reject('identify failed on image')
            })

            identify.on('close', code => {
                if (code > 0) { // if code is non-zero, remove the file because something is wrong with it
                    if (FS.existsSync(file)) FS.unlinkSync(file)
                    reject(`non-zero code from identify: ${code}`)
                }
            })

        } else {
            console.trace()
            reject(`image not found: ${file}`)
        }
    })
}

async function resize_image(file, max_dim = 600) { // max_dim is maximum dimension in either direction
    await mogrify(file, max_dim)
    return await getimagesize(file) // return the new image dimensions
}

function mogrify(file, max_dim = 600) { // max_dim is maximum dimension in either direction
    return new Promise(function(resolve, reject) {
        if (FS.existsSync(file)) {
            let { spawn } = require('child_process')
            let mogrify   = spawn('mogrify', ['-resize', max_dim, file]) // /usr/bin/mogrify -resize $max_dim $file

            mogrify.on('close', code => {
                if (code > 0) {
                    console.trace()
                    reject(`mogrify error: ${code}`) // todo: if code is non-zero, remove the file because something is wrong with it
                }
                else resolve(true)
            })
        } else {
            console.trace()
            reject(`image not found: ${file}`)
        }
    })
}

function valid_nonce(context) {

    const ip    = context.ip
    const ts    = _GET(context.req.url, 'ts')
    const nonce = _GET(context.req.url, 'nonce')

    if (intval(ts) < (Date.now() - 7200000)) return false // don't accept timestamps older than two hours

    if (get_nonce(ts, ip) === nonce) return true
    else                             return false
}

function get_nonce(ts, ip) {
    // create or check a nonce string for input forms. this makes each form usable only once, and only from the ip that got the form.
    // hopefully this slows down spammers and cross-site posting tricks
    return md5(ip + CONF.nonce_secret + ts)
}

function render_date(gmt_date, utz='America/Los_Angeles', format='YYYY MMM D, h:mma') { // create localized date string from gmt date out of mysql
    return MOMENT(Date.parse(gmt_date)).tz(utz).format(format)
}


function create_nonce_parms(ip) {
    let ts = Date.now() // current unix time in ms
    let nonce = get_nonce(ts, ip)
    return `ts=${ts}&nonce=${nonce}`
}

function is_user_banned(bans, topic, current_user) {
    let ban = bans.filter(item => (item.topic === topic))[0] // there should be only one per topic
    let utz = current_user ? current_user.user_timezone : 'America/Los_Angeles'
    return ban ? `banned from ${ban.topic} until ${render_date(ban.until, utz)}` : ''
}

function slugify(s) { // url-safe pretty chars only; not used for navigation, only for seo and humans
    return s.replace(/\W+/g,'-').toLowerCase().replace(/-+/,'-').replace(/^-+|-+$/,'')
}

function post2path(post) {
    let slug = JSON.stringify(post.post_date).replace(/"/g, '').substring(0, 10) + '-' + slugify(`${post.post_title}`)
    return `/post/${post.post_id}/${slug}`
}

function maybe(path) { // maybe the object path exists, maybe not
    // we pass in a string, evaluate as an object path, then return the value or null
    // if some object path does not exit, don't just bomb with "TypeError: Cannot read property 'whatever' of null"

    let start = path.split('.')[0]

    try      { return path.split('.').slice(1).reduce((curr, key)=>curr[key], start) }
    catch(e) { return null }
}

function invalid_nonce_message() {
    return `invalid nonce. reload this page and try again`
}

function get_external_links(content) {
    let c = CHEERIO.load(content)
    let extlinks = []

    c('a').each(function(i, elem) {

        if (!c(this).attr('href')) return // sometimes we get an a tag without an href, not sure how, but ignore them

        if (!(['http:', 'https:'].indexOf(URL.parse(c(this).attr('href')).protocol) > -1)) return // ignore invalid protocols

        let host = URL.parse(c(this).attr('href')).host
        if (new RegExp(CONF.domain).test(host)) return // ignore links back to own domain

        extlinks.push(c(this).attr('href'))
    })

    return extlinks
}

function clean_upload_path(path, filename, current_user) {

    if (!current_user) return ''

    // allow only alphanum, dot, dash in image name to mitigate scripting tricks
    // lowercase upload names so we don't get collisions on stupid case-insensitive Mac fs between eg "This.jpg" and "this.jpg"
    filename = filename.replace(/[^\w\.-]/gi, '').toLowerCase()

    var ext
    var matches
    if (matches = filename.match(/(\.\w{3,4})$/)) ext = matches[1] // include the dot, like .png

    if (filename.length > 128 ) filename = md5(filename) + ext // filename was too long to be backed up, so hash it to shorten it

    // prepend user_id to image so that we know who uploaded it, and so that other users cannot overwrite it
    filename = `${current_user.user_id}_${filename}`

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

function which_page(page, order) { // tell homepage, search, userpage, topic which page we are on
    let curpage = Math.floor(page) ? Math.floor(page) : 1
    let slimit  = (curpage - 1) * 20 + ', 20' // sql limit for pagination of results.
    let orders = { // maps order parm to a posts table column name to order by
        'active'   : 'post_modified',
        'comments' : 'post_comments',
        'likes'    : 'cast(post_likes as signed) - cast(post_dislikes as signed)',
        'new'      : 'post_date',
    }

    order = orders[order] ? order : 'active'

    let order_by = 'order by ' + orders[order] + ' desc'

    return [curpage, slimit, order, order_by]
}

function _GET(url, parm) { // given a string, return the GET parameter by that name
    if (!url) return ''
    return URL.parse(url, true).query[parm] || '' // always return a string so string methods like trim will work even if parm undefined
}

async function get_post(post_id, db, user_id) {
    if (user_id) return await get_row(`select * from posts
                                       left join postvotes on (postvote_post_id=post_id and postvote_user_id=?)
                                       left join postviews on (postview_post_id=post_id and postview_user_id=?)
                                       left join users on user_id=post_author where post_id=?`,
                                       [user_id, user_id, post_id], db)
    
    return await get_row(`select * from posts left join users on user_id=post_author where post_id = ?`, [post_id], db)
}

async function user_topic_bans(user_id, db) {
    return await query(`select topicwatch_name as topic, topicwatch_banned_until as until from topicwatches
                        where topicwatch_user_id=? and topicwatch_banned_until > now()`, [user_id], db)
}

async function update_prev_next(post_topic, post_id, db) { // slow, so do this only when post is changed or the prev or next is null

    if (!post_topic || !post_id) return

    let prev = intval(await get_var(`select max(post_id) as prev from posts
                                     where post_topic=? and post_id < ? and post_approved=1 limit 1`, [post_topic, post_id], db))

    let next = intval(await get_var(`select min(post_id) as next from posts
                                     where post_topic=? and post_id > ? and post_approved=1 limit 1`, [post_topic, post_id], db))

    await query(`update posts set post_prev_in_topic=?, post_next_in_topic=? where post_id=?`, [prev, next, post_id], db)

    return [prev, next]
}

async function too_fast(ip, db) { // rate limit comment insertion by user's ip address
    const ago = await get_var(`select (unix_timestamp(now()) - unix_timestamp(user_last_comment_time)) as ago from users
                               where user_last_comment_time is not null and user_last_comment_ip = ?
                               order by user_last_comment_time desc limit 1`, [ip], db)

    return (ago && ago < 2) ? true : false // return true if this ip already commented less than two seconds ago
}

async function send_login_link(ip, db, post_data) {

    if (!valid_email(post_data.user_email)) return `Please go back and enter a valid email`

    let key      = get_nonce(Date.now(), ip)
    let key_link = `${BASEURL}/key_login?key=${ key }`

    var results = await query('update users set user_activation_key=? where user_email=?', [key, post_data.user_email], db)

    if (results.changedRows) {

        let message = `Click here to log in and get your password: <a href='${ key_link }'>${ key_link }</a>`

        mail(post_data.user_email, `Your ${ CONF.domain } login info`, message)

        return `Please check your ${post_data.user_email} email for the login link`
    }
    else return `Could not find user with email ${ post_data.user_email }`
}

async function reset_latest_comment(post_id, db) { // reset post table data about latest comment, esp post_modified time

    if (!post_id) return

    let comment_row = await get_row(`select * from comments where comment_post_id=? and comment_approved > 0
                                     order by comment_date desc limit 1`, [post_id], db)

    if (comment_row) { // this is at least one comment on this post
        let post_comments = await get_var(`select count(*) as c from comments where comment_post_id=? and comment_approved=1`, [post_id], db)

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
                      post_id], db) // post_modified is necessary for sorting posts by latest comment
    }
    else { // there are no comments
        await query(`update posts set
                     post_modified=post_date,
                     post_comments=0,
                     post_latest_comment_id=0,
                     post_latest_commenter_id=0,
                     post_latest_comment_excerpt=''
                     where post_id=?`, [post_id], db)
    }
}

async function repair_referer(req, db) { // look at referer to a bad post; if it exist, call update_prev_next() on that

    if (!req.headers.referer) return

    var matches
    if (matches = req.headers.referer.match(/\/post\/(\d+)/m)) {
        var referring_post_id = intval(matches[1])

        var post = await get_post(referring_post_id, db)

        if (post && post.post_topic) await update_prev_next(post.post_topic, post.post_id, db)
    }
}

function redirect(redirect_to, context, code=303) { // put the code at the end; then if it isn't there we get a default

    var message = `Redirecting to ${ redirect_to }`

    var headers =  {
      'Location'       : redirect_to,
      'Content-Length' : message.length,
      'Expires'        : new Date().toUTCString()
    }

    send(code, headers, message, context)
}

async function get_moderator(topic, db) {
    topic = topic.replace(/\W/, '') // topic names contain only \w chars
    return await get_var('select topic_moderator from topics where topic=?', [topic], db)
}

function get_offset(total, url) {
    let offset = (total - 40 > 0) ? total - 40 : 0                // if offset is not set, select the 40 most recent comments
    if (_GET(url, 'offset')) offset = intval(_GET(url, 'offset')) // but if offset is set, use that instead

    return offset
}

async function post_comment_list(post, context) {

    let offset = get_offset(post.post_comments, context.req.url)

    // anon users see their own comments whether out of moderation or not
    let user_id = context.current_user ? context.current_user.user_id : 0
    let sql = `select sql_calc_found_rows * from comments
               left join users on comment_author=user_id
               left join commentvotes on (comment_id = commentvote_comment_id and commentvote_user_id = ?)
               where comment_post_id = ? and (comment_approved = 1 or user_name='${ip2anon(context.ip)}' or comment_author = ?)
               order by comment_date limit 40 offset ?`

    let comments = await query(sql, [user_id, post.post_id, user_id, offset], context.db)
    let found_rows = comments.found_rows

    let topic_moderator = await get_moderator(post.post_topic, context.db)

    // add in the comment row number to the result here for easier pagination info; would be better to do in mysql, but how?
    // also add in topic_moderator so we can display del link
    comments = comments.map(comment => {
        comment.row_number = ++offset
        comment.topic_moderator = topic_moderator
        return comment
    })

    comments.found_rows = found_rows // have to put this after map() above to retain it

    return comments
}

async function post_summons(post, db, already_mailed) { // post_content contains a summons like @user, and user is user_summonable, so email user the post

    var matches
    if (matches = post.post_content.match(/@(\w+)/m)) { // just use the first @user in the post, not multiple
        var summoned_user_username = matches[1]
        var u
        if (u = await get_row(`select * from users where user_name=? and user_id != ? and user_summonable=1`,
                                   [summoned_user_username, post.post_author], db)) {

            let subject  = `New ${CONF.domain} post by ${post.user_name} directed at ${summoned_user_username}`

            let notify_message  = `<html><body><head><base href="${BASEURL}" ></head>
            New post by ${post.user_name}:  <a href='${BASEURL}${post2path(post)}'>${post.post_title}</a><p>
            <p>${post.post_content}<p>
            <p><a href='${BASEURL}${post2path(post)}'>Reply</a><p>
            <font size='-1'>Stop allowing <a href='${BASEURL}/profile'>@user summons</a></font></body></html>`

            if (u.user_email) mail(u.user_email, subject, notify_message) // user_email could be null in db

            // include in already_mailed so we don't duplicate post emails for other reasons
            already_mailed[u.user_id] ? already_mailed[u.user_id]++ : already_mailed[u.user_id] = 1
        }
    }

    return already_mailed
}

async function post_followers(post, db, already_mailed) { // now do user follower emails

    let rows = []
    if (rows = await query(`select distinct rel_self_id as user_id from relationships where rel_other_id = ? and rel_i_follow > 0`,
                           [post.post_author], db)) {
        rows.forEach(async function(row) {

            if (already_mailed[row.rel_self_id]) return

            let u = await get_userrow(row.rel_self_id, db)

            if (!u) return

            let subject = `New ${CONF.domain} post by ${post.user_name}`

            let notify_message  = `<html><body><head><base href="${BASEURL}" ></head>
            New post by ${post.user_name}, <a href='${BASEURL}${post2path(post)}'>${post.post_title}</a>:<p>
            <p>${post.post_content}<p>\r\n\r\n
            <p><a href='${BASEURL}${post2path(post)}'>Reply</a><p>
            <font size='-1'>Stop following <a href='${BASEURL}/user/${post.user_name}'>${post.user_name}</a></font><br>`

            mail(u.user_email, subject, notify_message)
            already_mailed[u.user_id] ? already_mailed[u.user_id]++ : already_mailed[u.user_id] = 1
        })
    }

    return already_mailed
}

async function topic_followers(post, db, already_mailed) {

    // now do topic follower emails
    if (post.post_topic) {
        let rows = []
        if (rows = await query(`select distinct topicwatch_user_id from topicwatches where topicwatch_name = ?`, [post.post_topic], db)) {
            rows.forEach(async function(row) {

                if (already_mailed[row.topicwatch_user_id]) return

                let u = await get_userrow(row.topicwatch_user_id, db)

                if (!u) return

                let subject = `New ${CONF.domain} post in ${post.post_topic}`

                let notify_message  = `<html><body><head><base href="${BASEURL}" ></head>
                New post in ${post.post_topic} by ${post.user_name}, <a href='${BASEURL}${post2path(post)}'>${post.post_title}</a>:<p>
                <p>${post.post_content}<p>\r\n\r\n
                <p><a href='${BASEURL}${post2path(post)}'>Reply</a><p>
                <font size='-1'>Stop following <a href='${BASEURL}/topic/${post.post_topic}'>${post.post_topic}</a></font><br>`

                mail(u.user_email, subject, notify_message)
                already_mailed[u.user_id] ? already_mailed[u.user_id]++ : already_mailed[u.user_id] = 1
            })
        }
    }

    return already_mailed
}

async function post_mail(p, db) { // reasons to send out post emails: @user, user following post author, user following post topic

    let post = await get_row(`select * from posts, users where post_id=? and post_author=user_id`, [p], db) // p is just the post_id

    let already_mailed = []

    already_mailed = already_mailed.concat(post_summons(   post, db, already_mailed.slice())) // slice() so we don't modify array in fn, would be impure
    already_mailed = already_mailed.concat(post_followers( post, db, already_mailed.slice()))
    already_mailed = already_mailed.concat(topic_followers(post, db, already_mailed.slice()))
}

async function login(email, password, context) {

    const user = await get_row('select * from users where user_email = ? and user_pass = ?', [email, md5(password)], context.db)

    const login_failed_email = user ? null                   : email
    const current_user       = user ? user                   : null
    const user_id            = user ? current_user.user_id   : ''
    const user_pass          = user ? current_user.user_pass : ''

    if ('post_login' === context.page) var content = icon_or_loginprompt(current_user, login_failed_email)
    if ('key_login'  === context.page) {
        var content = html(
            render_query_times(context.res.start_time, context.db.queries),
            head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
            header(context),
            midpage(
                h1(`Your password is ${ password } and you are now logged in`)
            )
        )
    }

    const usercookie = `${ CONF.usercookie }=${ user_id   }`
    const pwcookie   = `${ CONF.pwcookie   }=${ user_pass }`
    const d          = new Date()
    const decade     = new Date(d.getFullYear()+10, d.getMonth(), d.getDate()).toUTCString()
    const headers    = [ // you must use the undocumented "array" feature of writeHead to set multiple cookies, because json
        ['Content-Length' , content.length                            ],
        ['Content-Type'   , 'text/html'                               ],
        ['Expires'        , d.toUTCString()                           ],
        ['Set-Cookie'     , `${usercookie}; Expires=${decade}; Path=/`],
        ['Set-Cookie'     , `${pwcookie};   Expires=${decade}; Path=/`]
    ] // do not use 'secure' parm with cookie or will be unable to test login in dev, bc dev is http only

    send(200, headers, content, context)
}

async function ip2country(ip, db) { // probably a bit slow, so don't overuse this
    if (!ip) return
    ip = ip.replace(/[^0-9\.]/, '')
    return await get_var(`select country_name from countries where inet_aton(?) >= country_start and inet_aton(?) <= country_end`, [ip, ip], db)
}

async function get_userrow(user_id, db) {
    return await get_row('select * from users where user_id = ?', [user_id], db)
}

async function get_user_by_name(user_name, db) {
    return await get_row('select * from users where user_name = ?', [user_name], db)
}

async function get_comment_list_by_author(user, num, db, url) {
    let offset = get_offset(user.user_comments, url)
    return await query(`select sql_calc_found_rows * from comments left join users on comment_author=user_id
                        where user_name = ? order by comment_date limit ? offset ?`, [user.user_name, num, offset], db)
}

async function get_comment_list_by_number(n, offset, num, db) {
    return await query(`select sql_calc_found_rows * from comments, users force index (user_comments_index)
                        where comments.comment_author = users.user_id and user_comments = ? order by comment_date desc limit ? offset ?`,
                        [n, num, offset], db)
}

async function get_comment_list_by_search(s, offset, num, db) {
    return await query(`select sql_calc_found_rows * from comments left join users on comment_author=user_id
                        where match(comment_content) against (?) order by comment_date desc limit ? offset ?`, [s, num, offset], db)
}

async function find_or_create_anon(db, ip) { // find the user_id derived from this anonymous ip address; if dne, create

    var user_id
    user_id = await get_var('select user_id from users where user_name = ?', [ip2anon(ip)], db)

    if (!user_id) {
        var results = await query('insert into users (user_name, user_registered) values (?, now())', [ip2anon(ip)], db)
        var user_id = results.insertId
        if (!user_id) throw { code : 500, message : `failed to create anon user ${ip2anon(ip)}`, }
    }

    return user_id
}

async function comment_summons_mail(c, p, offset, already_mailed, db) {

    // if comment_content contains a summons like @user, and user is user_summonable, then email user the comment
    var matches
    if (matches = c.comment_content.match(/@(\w+)/m)) { // just use the first @user in the comment, not multiple
        let summoned_user_username = matches[1]
        var u
        if (u = await get_row(`select * from users where user_name=? and user_id != ? and user_summonable=1`,
                                   [summoned_user_username, c.comment_author], db)) {

            let subject  = `New ${CONF.domain} comment by ${c.user_name} directed at ${summoned_user_username}`

            let notify_message  = `<html><body><head><base href="${BASEURL}" ></head>
            New comment by ${c.user_name} in <a href='${BASEURL}${post2path(p)}'>${p.post_title}</a>:<p>
            <p>${c.comment_content}<p>
            <p><a href='${BASEURL}${post2path(p)}?offset=${offset}#comment-${c.comment_id}'>Reply</a><p>
            <font size='-1'>Stop allowing <a href='${BASEURL}/profile'>@user summons</a></font></body></html>`

            if (u.user_email) mail(u.user_email, subject, notify_message) // user_email could be null in db

            // include in already_mailed so we don't duplicate emails below
            already_mailed[u.user_id] ? already_mailed[u.user_id]++ : already_mailed[u.user_id] = 1
        }
    }

    return already_mailed
}

async function following_post_mail(c, p, offset, already_mailed, db) {

    // commenter logged in right now probably doesn't want to get his own comment in email
    // select all other subscriber user ids and send them the comment by mail
    let sql = `select postview_user_id, postview_post_id from postviews
                    where postview_post_id=? and postview_want_email=1 and postview_user_id != ?
                    group by postview_user_id` // group by so that user_id is in there only once.

    let rows = []
    if (rows = await query(sql, [c.comment_post_id, c.comment_author], db)) {
        rows.forEach(async function(row) {

            if (already_mailed[row.postview_user_id]) return

            let u = await get_userrow(row.postview_user_id, db)
            if (!u) return

            let subject = `New ${CONF.domain} comment in '${p.post_title}'`

            let notify_message  = `<html><body><head><base href="${BASEURL}" ></head>
            New comment by ${c.user_name} in <a href='${BASEURL}${post2path(p)}'>${p.post_title}</a>:<p>
            <p>${c.comment_content}<p>\r\n\r\n
            <p><a href='${BASEURL}${post2path(p)}?offset=${offset}#comment-${c.comment_id}'>Reply</a><p>
            <font size='-1'>Stop watching <a href='${BASEURL}${post2path(p)}?want_email=0'>${p.post_title}</a></font><br>
            <font size='-1'>Stop watching <a href='${BASEURL}/autowatch?off=true'>all posts</a></font></body></html>`

            mail(u.user_email, subject, notify_message)
            already_mailed[u.user_id] ? already_mailed[u.user_id]++ : already_mailed[u.user_id] = 1
        })
    }

    return already_mailed
}

async function comment_mail(c, db) { // reasons to send out comment emails: @user summons, user watching post

    const p      = await get_post(c.comment_post_id, db)
    const offset = await cid2offset(p.post_id, c.comment_id, db)

    let already_mailed = []
    already_mailed = already_mailed.concat(comment_summons_mail(c, p, offset, already_mailed.slice(), db))
    already_mailed = already_mailed.concat(following_post_mail( c, p, offset, already_mailed.slice(), db))
}

async function cid2offset(post_id, comment_id, db) { // given a comment_id, find the offset
    return await get_var(`select floor(count(*) / 40) * 40 as o from comments
                          where comment_post_id=? and comment_id < ? order by comment_id`, [post_id, comment_id], db)
}

function die(message, context) {

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            h1(message)
        )
    )

    send_html(200, content, context)
}

async function allow_comment(post_data, context) {

    if (!valid_nonce(context))                       return { err: true, content: popup(invalid_nonce_message()) }
    if (!post_data.comment_content)                  return { err: true, content: '' } // empty comment, empty response
    if (await too_fast(context.ip, context.db))      return { err: true, content: popup('You are posting comments too quickly') }
    if (await already_said_that(post_data, context)) return { err: true, content: popup('you already said that') }

    let bans = await user_topic_bans(post_data.comment_author, context.db)
    let topic = (await get_post(post_data.comment_post_id, context.db)).post_topic
    let message = is_user_banned(bans, topic, context.current_user)
    if (message) return { err: true, content: popup(message) }

    return { err: false, content: '' }
}

async function already_said_that(post_data, context) { // select the most recent comment by that user in that thread; if same as comment_content, return true
    const most_recent = await get_var(`select comment_content from comments where comment_post_id=? and comment_author=?
                                       order by comment_date desc limit 1`, [post_data.comment_post_id, post_data.comment_author], context.db)
    
    return (most_recent == post_data.comment_content) ? true : false
}

async function after_accept_comment(comment, context) {

    await reset_latest_comment(comment.comment_post_id, context.db)

    if (context.current_user) { // update postviews so that user does not see his own comment as unread
        await query(`insert into postviews (postview_user_id, postview_post_id, postview_last_view)
                     values (?, ?, now()) on duplicate key update postview_last_view=now()`,
                     [context.current_user.user_id, comment.comment_post_id], context.db)
    }

    // update comment count whether logged in or anon user
    await query(`update users set user_last_comment_ip = ?,
                 user_comments=(select count(*) from comments where comment_author = ?)
                 where user_id = ?`, [context.ip, comment.comment_author, comment.comment_author], context.db)

    if (!comment.comment_approved) { // email moderator if comment not approved
        //mail(CONF.admin_email, 'new comment needs review', `${comment.comment_content}<p><a href='https://${CONF.domain}/comment_moderation'>moderation page</a>`)
    }
    else comment_mail(comment, context.db)
}

async function hit_daily_post_limit(context) {

    if (!context.current_user) return true

    var posts_today = await get_var('select count(*) as c from posts where post_author=? and post_date >= curdate()',
        [context.current_user.user_id], context.db)

    var whole_weeks_registered = await get_var('select floor(datediff(curdate(), user_registered)/7) from users where user_id=?',
        [context.current_user.user_id], context.db)

    return (posts_today >= CONF.max_posts || posts_today > whole_weeks_registered) ? true : false
}

function find_topic(post_content) {

    let matches

    if      (matches = post_content.match(/^#(\w+)/m)) return matches[1] // first tag starting a line becomes topic
    else if (matches = post_content.match(/>#(\w+)/m)) return matches[1] // else existing, linked topic
    else                                               return 'misc'
}

async function comment_id2topic(comment_id, context) {
   const cid = intval(comment_id)
   if (!cid) return ''

   return await get_var('select post_topic from posts left join comments on post_id=comment_post_id where comment_id = ?', [cid], context.db)
}

async function like_comment(user_id, user_name, context) {
    let comment_id  = intval(_GET(context.req.url, 'comment_id'))
    let comment_row = await get_row(`select * from comments where comment_id=?`, [comment_id], context.db)

    if (!comment_row) return ''

    let vote = await get_row(`select commentvote_up, count(*) as c from commentvotes where commentvote_user_id=? and commentvote_comment_id=?`,
                              [user_id, comment_id], context.db)

    if (vote && vote.c) return `&#8593;&nbsp; you like this (${comment_row.comment_likes})`
    else {
        await query(`update comments set comment_likes=comment_likes+1 where comment_id=?`, [comment_id], context.db)

        await query(`insert into commentvotes (commentvote_user_id, commentvote_comment_id, commentvote_up) values (?, ?, 1)
                     on duplicate key update commentvote_up=1`, [user_id, comment_id], context.db)

        await query(`update users set user_likes=user_likes+1 where user_id=?`, [comment_row.comment_author], context.db)

        if (1 === user_id) await query(`update users set user_pbias=user_pbias+1 where user_id=?`, [comment_row.comment_author], context.db)

        return `&#8593;&nbsp;you like this (${comment_row.comment_likes + 1})`
    }
}

async function send_comment_like_email(user_name, context) {
    let comment_id = intval(_GET(context.req.url, 'comment_id'))
    let comment    = await get_row(`select * from comments where comment_id=?`, [comment_id], context.db)

    // Now mail the comment author that his comment was liked, iff he has user_summonable set
    // todo: AND if current user has no record of voting on this comment! (to prevent clicking like over and over to annoy author with email)
    let offset = await cid2offset(comment.comment_post_id, comment.comment_id, context.db)
    let comment_url = `https://${CONF.domain}/post/${comment.comment_post_id}?offset=${offset}#comment-${comment.comment_id}`

    let u = await get_row(`select * from users where user_id=?`, [comment.comment_author], context.db)

    if (intval(u && u.user_summonable)) {

        let subject  = `${user_name} liked your comment`

        let message = `<html><body><head><base href='https://${CONF.domain}/' ></head>
        <a href='https://${CONF.domain}/user/${user_name}' >${user_name}</a> liked the comment you made here:<p>\r\n\r\n
        <a href='${comment_url}' >${comment_url}</a><p>${comment.comment_content}<p>\r\n\r\n
        <font size='-1'>Stop getting <a href='https://${CONF.domain}/edit_profile#user_summonable'>notified of likes</a>
        </font></body></html>
        ` // nice to have a newline at the end when getting pages on terminal

        mail(u.user_email, subject, message)
    }
}

async function like_post(user_id, context) {
    let post_id = intval(_GET(context.req.url, 'post_id'))

    let vote = await get_row(`select postvote_up, count(*) as c from postvotes where postvote_user_id=? and postvote_post_id=?`,
                             [user_id, post_id], context.db)

    if (vote && vote.c) { // if they have voted before on this, just return
        let post = await get_post(post_id, context.db)
        return String(post.post_likes)
    }

    await query(`update posts set post_likes=post_likes+1 where post_id=?`, [post_id], context.db)

    await query(`insert into postvotes (postvote_user_id, postvote_post_id, postvote_up) values (?, ?, 1)
                 on duplicate key update postvote_up=0`, [user_id, post_id], context.db)

    let post = await get_post(post_id, context.db)

    await query(`update users set user_likes=user_likes+1 where user_id=?`, [post.post_author], context.db)

    return String(post.post_likes)
}

async function send_post_like_email(user_name, context) {
    let post_id = intval(_GET(context.req.url, 'post_id'))
    let post = await get_post(post_id, context.db)

    let post_url = 'https://' + CONF.domain +  post2path(post)
    let u = await get_row(`select * from users where user_id=?`, [post.post_author], context.db)
    if (intval(u && u.user_summonable)) {

        let subject  = `${user_name} liked your post`

        let message = `<html><body><head><base href='https://${CONF.domain}/' ></head>
        <a href='https://${CONF.domain}/user/${user_name}' >${user_name}</a>
            liked the post you made here:<p>\r\n\r\n
        <a href='${post_url}' >${post_url}</a><p>${post.post_content}<p>\r\n\r\n
        <font size='-1'>Stop getting <a href='https://${CONF.domain}/edit_profile#user_summonable'>notified of likes</a>
        </font></body></html>`

        mail(u.user_email, subject, message)
    }
}

async function comments_to_moderate(context) {

    if (!context.current_user) return []

    // if user is not superuser, then limit to comments in topics user is moderating
    const topic_constraint = (context.current_user.user_id != 1) ?  `and post_topic in ('${context.current_user.is_moderator_of.join("','")}')` : ''

    return await query(`select * from comments left join users on user_id=comment_author left join posts on post_id=comment_post_id where
                        (comment_approved = 0 or comment_approved is null) ${topic_constraint}`, [], context.db)
}

async function dislike_comment(user_id, context) {

    let comment_id  = intval(_GET(context.req.url, 'comment_id'))
    let comment_row = await get_row(`select * from comments where comment_id=?`, [comment_id], context.db)
    let vote        = await get_row(`select commentvote_up, count(*) as c from commentvotes where commentvote_user_id=? and commentvote_comment_id=?`,
                                    [user_id, comment_id], context.db)

    if (vote.c) return `&#8595;&nbsp; you dislike this (${comment_row.comment_dislikes})` // already voted on this comment

    await query(`update comments set comment_dislikes=comment_dislikes+1 where comment_id=?`, [comment_id], context.db)

    await query(`insert into commentvotes (commentvote_user_id, commentvote_comment_id, commentvote_down) values (?, ?, 1)
                 on duplicate key update commentvote_up=1`, [user_id, comment_id], context.db)

    await query(`update users set user_dislikes=user_dislikes+1 where user_id=?`, [comment_row.comment_author], context.db)

    // Now if admin was the disliker, then the user gets a bias bump down.
    if (1 === user_id) await query(`update users set user_pbias=user_pbias-1 where user_id=?`, [comment_row.comment_author], context.db)

    return `&#8595;&nbsp;you dislike this (${comment_row.comment_dislikes + 1})`
    // no emailing done of dislikes
}

async function dislike_post(user_id, context) {
    let post_id = intval(_GET(context.req.url, 'post_id'))

    let vote = await get_row(`select postvote_down, count(*) as c from postvotes where postvote_user_id=? and postvote_post_id=?`,
                              [user_id, post_id], context.db)

    if (vote.c) { // if they have voted before on this, just return
        let post_row = await get_post(post_id, context.db)
        return String(post_row.post_dislikes)
    }

    await query(`update posts set post_dislikes=post_dislikes+1 where post_id=?`, [post_id], context.db)

    await query(`insert into postvotes (postvote_user_id, postvote_post_id, postvote_down) values (?, ?, 1) on duplicate key update postvote_down=0`,
                [user_id, post_id], context.db)

    let post_row = await get_post(post_id, context.db)

    await query(`update users set user_dislikes=user_dislikes+1 where user_id=?`, [post_row.post_author], context.db)

    return String(post_row.post_dislikes)
}

async function check_topic(p, context) { // if we never set prev|next (null) or did set it to 0 AND are here from a new post referer, then update
    if ((null === p.post_prev_in_topic || null === p.post_next_in_topic) ||
        ((0   === p.post_prev_in_topic || 0    === p.post_next_in_topic) &&
            context.req.headers.referer &&
            context.req.headers.referer.match(/post/))
       ) [p.post_prev_in_topic, p.post_next_in_topic] = await update_prev_next(p.post_topic, p.post_id, context.db)
}

async function penalize(comment_author, context) { // decrement user_pbias
    if (context.current_user.user_id === comment_author) return // you can't penalize yourself
    await query(`update users set user_pbias=user_pbias-1 where user_id=?`, [comment_author], context.db)
}

async function check_post(p, context) {

    if (!p) {
        await repair_referer(context.req, context.db)
        return 'No post with that id'
    }

    if (!p.post_approved) {
        await repair_referer(context.req, context.db)
        return 'That post is waiting for moderation'
    }
}

async function update_postview(p, context) {

    p.postview_want_email = p.postview_want_email || 0 // keep as 1 or 0 from db; set to 0 if null in db

    if('0' === _GET(context.req.url, 'want_email')) p.postview_want_email = 0

    await query(`replace into postviews set postview_user_id=?, postview_post_id=?, postview_last_view=now(), postview_want_email=?`,
                [context.current_user.user_id, p.post_id, p.postview_want_email], context.db)
}

async function get_unrequited(context, d, ob, offset) {
    // 1. Find all those IDs that asked to be friends with user_id.
    await query('create temporary table unrequited select * from relationships where rel_other_id=? and rel_my_friend > 0',
          [context.current_user.user_id], context.db)

    // 2. Subtract all those for which there is the acceptance line.
    await query(`delete from unrequited where rel_self_id in (select rel_other_id from relationships where rel_self_id=? and rel_my_friend > 0)`,
                [context.current_user.user_id], context.db)
    
    const message = `Unrequited Friendship Requests For ${context.current_user.user_name}`
    const users   =  await query(`select sql_calc_found_rows * from unrequited, users
                         where unrequited.rel_self_id = users.user_id and user_id = ? limit 40 offset ${offset}`,
                        [context.current_user.user_id], context.db)

    return [message, users]
}

async function get_followersof(context, d, ob, offset) {
    const followersof = intval(_GET(context.req.url, 'followersof'))
    const message = 'Followers of ' + (await get_userrow(followersof, context.db)).user_name
    const users = await query(`select sql_calc_found_rows * from users
        where user_id in (select rel_self_id from relationships where rel_other_id=? and rel_i_follow > 0)
        order by ${ob} ${d} limit 40 offset ${offset}`, [followersof, ob, d], context.db)

    // keep followers-count cache in users table correct
    await query('update users set user_followers=? where user_id=?', [users.length, followersof], context.db)

    return [message, users]
}

async function get_following(context, d, ob, offset) {
    const following = intval(_GET(context.req.url, 'following'))
    const message = 'Users ' + (await get_userrow(following, context.db)).user_name + ' is Following'
    const users = await query(`select sql_calc_found_rows * from users where user_id in
                        (select rel_other_id from relationships where rel_self_id=? and rel_i_follow > 0) order by ${ob} ${d} limit 40 offset ${offset}`,
                        [following], context.db)

    return [message, users]
}

async function get_friendsof(context, d, ob, offset) {
    const friendsof = intval(_GET(context.req.url, 'friendsof'))
    const message = 'Friends of ' + (await get_userrow(friendsof, context.db)).user_name
    const users = await query(`select sql_calc_found_rows * from users where user_id in
                              (select r1.rel_other_id from relationships as r1, relationships as r2 where
                                  r1.rel_self_id=? and
                                  r1.rel_self_id=r2.rel_other_id and
                                  r2.rel_self_id=r1.rel_other_id and
                                  r1.rel_my_friend > 0 and r2.rel_my_friend > 0)
                              order by ${ob} ${d} limit 40 offset ${offset}`, [friendsof, ob, d], context.db)

    await query(`update users set user_friends=? where user_id=?`, [users.length, friendsof], context.db) // Keep friends-count cache correct.

    return [message, users]
}

async function get_user_name(context, d, ob, offset) {

    let user_name = _GET(context.req.url, 'user_name').replace(/[^a-zA-Z0-9._ -]/).substring(0, 40)
    user_name = user_name.trim().replace('/_/', '\_') // bc _ is single-char wildcard in mysql matching.
    const message = `Users With Names Like '${user_name}'`
    const users = await query(`select sql_calc_found_rows * from users where user_name like '%${user_name}%'
                               order by ${ob} ${d} limit 40 offset ${offset}`, [ob, d], context.db)
    return [message, users]
}

async function get_users(context, d, ob, offset) {
    const message = 'users'
    const users =  await query(`select sql_calc_found_rows * from users order by ${ob} ${d} limit 40 offset ${offset}`, [], context.db)
    return [message, users]
}

async function get_image_path(mkdirp = require('mkdirp')) {

    return new Promise(function(resolve, reject) {
        let d        = new Date()
        let mm       = ('0' + (d.getMonth() + 1)).slice(-2)
        let url_path = `/${CONF.upload_dir}/${d.getFullYear()}/${mm}`
        let abs_path = `${CONF.doc_root}${url_path}`

        mkdirp(abs_path, function (err) {
            if (err) {
                console.error(err)
                reject(err)
            }
            else resolve([url_path, abs_path])
        })
    })
}

async function update_icon(path, dims, context) {
    let id = context.current_user.user_id
    await query(`update users set user_icon        = ? where user_id = ?`, [path,    id], context.db)
    await query(`update users set user_icon_width  = ? where user_id = ?`, [dims[0], id], context.db)
    await query(`update users set user_icon_height = ? where user_id = ?`, [dims[1], id], context.db)
}

routes.GET.about = async function(context) {
    redirect(`/post/${CONF.about_post_id}`, context)
}

routes.POST.accept_comment = async function(context) { // insert new comment

    let post_data = await collect_post_data_and_trim(context)

    if (context.current_user && context.current_user.user_id) {
        post_data.comment_author = context.current_user.user_id
        post_data.comment_approved = 1
    }
    else {
        post_data.comment_author = await find_or_create_anon(context.db, context.ip)
        post_data.comment_approved = 0 // anon comments go into moderation
        //return send_json(200, { err: true, content: popup('anonymous comments have been disabled, please reg/login') }, context)
    }

    let result = await allow_comment(post_data, context)
    if (result.err) return send_json(200, result, context)

    post_data.comment_content = strip_tags(post_data.comment_content.linkify())
    post_data.comment_date    = new Date().toISOString().slice(0, 19).replace('T', ' ') // mysql datetime format

    try {
        var insert_result = await query('insert into comments set ?', post_data, context.db)
        var comment_id = insert_result.insertId
    }
    catch(e) {
        console.error(`${e} at accept_comment`)
        return send_json(200, { err: true, content: popup('database failed to accept some part of the content, maybe an emoticon') }, context)
    }

    let comment = await get_row('select * from comments left join users on comment_author=user_id where comment_id = ?', [comment_id], context.db)

    send_json(200, { err: false, content: format_comment(comment, context, context.comments, _GET(context.req.url, 'offset')) }, context)

    await after_accept_comment(comment, context)
}

routes.POST.accept_edited_comment = async function(context) { // update old comment

    if (!valid_nonce(context)) return die(invalid_nonce_message(), context)

    let post_data = await collect_post_data_and_trim(context)

    if (!post_data.comment_content) return die('please go back and enter some content', context)

    // rate limit by user's ip address
    if (await too_fast(context.ip, context.db)) return send_json(200, { err: true, content: popup('You are posting comments too quickly') }, context)

    post_data.comment_content  = strip_tags(post_data.comment_content.linkify())
    post_data.comment_dislikes = 0
    post_data.comment_likes    = 0
    post_data.comment_approved = 1

    let comment_id = post_data.comment_id
    await query('update comments set ? where comment_id = ? and (comment_author = ? or 1 = ?)',
                [post_data, comment_id, context.current_user.user_id, context.current_user.user_id], context.db)

    // now select the inserted row so that we pick up the comment_post_id
    let comment = await get_row('select * from comments where comment_id = ?', [comment_id], context.db)
    let offset  = await cid2offset(comment.comment_post_id, comment_id, context.db)
    redirect(`/post/${comment.comment_post_id}?offset=${offset}#comment-${comment_id}`, context)
}

routes.POST.accept_post = async function(context) { // insert new post or update old post

    if (!context.current_user) return die(`anonymous posts are not allowed`, context)

    let post_data = await collect_post_data_and_trim(context)

    post_data.post_topic    = find_topic(post_data.post_content)
    post_data.post_content  = strip_tags(post_data.post_content.linkify()) // remove all but a small set of allowed html tags
    post_data.post_approved = 1 // may need to be more restrictive if spammers start getting through

    // get all valid topics in an array; if post topic is not in that array, reject, asking for one of the #elements in array

    var p = intval(post_data.post_id)
    if (p) { // editing old post, do not update post_modified time because it confuses users
        await query('update posts set ? where post_id=?', [post_data, p], context.db)
    }
    else { // new post
        post_data.post_author = context.current_user.user_id

        if ((context.current_user.user_comments < 3) && is_foreign(context) && CHEERIO.load(post_data.post_content)('a').length)
            return die(`spam rejected`, context) // new, foreign, and posting link

        if (await hit_daily_post_limit(context)) return die(`you hit your new post limit for today`, context)

        try {
            var results = await query('insert into posts set ?, post_modified=now()', post_data, context.db)
            p = results.insertId
            if (!p) return die(`failed to insert ${post_data} into posts`, context)
        }
        catch (e) { return die(e, context) }

        post_mail(p, context.db) // reasons to send out post emails: @user, user following post author, user following post topic
    }

    await update_prev_next(post_data.post_topic, p, context.db)

    const post_row = await get_post(p, context.db)

    redirect(post2path(post_row), context)
}

routes.GET.approve_comment = async function(context) {

    const comment_id = intval(_GET(context.req.url, 'comment_id'))
    if (!comment_id)                                   return send_html(200, '', context)
    if (!context.current_user)                         return send_html(200, '', context)
    if (!valid_nonce(context))                         return send_html(200, '', context)

    const topic = await comment_id2topic(comment_id, context)

    if (!context.current_user.is_moderator_of.includes(topic) &&
        !context.current_user.user_level === 4) return send_html(200, '', context)

    await query('update comments set comment_approved=1, comment_date=now() where comment_id=?', [comment_id], context.db)

    const post_id = await get_var('select comment_post_id from comments where comment_id=?', [comment_id], context.db)
    await reset_latest_comment(post_id, context.db)

    send_html(200, '', context) // make it disappear from comment_moderation page
}

routes.GET.approve_post = async function(context) {

    let post_id = intval(_GET(context.req.url, 'post_id'))

    if (!post_id)                              return send_html(200, '', context)
    if (!context.current_user)                 return send_html(200, '', context)
    if (context.current_user.user_level !== 4) return send_html(200, '', context)
    if (!valid_nonce(context))                 return send_html(200, '', context)

    await query('update posts set post_approved=1, post_modified=now() where post_id=?', [post_id], context.db)

    send_html(200, '', context) // make it disappear from post_moderation page
}

routes.GET.autowatch = async function(context) {

    var current_user_id = context.current_user ? context.current_user.user_id : 0

    if (!current_user_id) die('must be logged in to stop watching all posts', context)

    // left joins to also get each post's viewing and voting data for the current user if there is one
    let sql = `update postviews set postview_want_email=0 where postview_user_id = ?`
    await query(sql, [current_user_id], context.db)

    var content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            h1(`All email of new post comments turned off`)
        )
    )

    return send_html(200, content, context)
}

routes.GET.ban_from_topic = async function(context) {

    if (!valid_nonce(context)) return send_html(200, invalid_nonce_message(), context)

    let user_id = intval(_GET(context.req.url, 'user_id'))
    if (!user_id) return send_html(200, 'missing user_id', context)

    let topic = _GET(context.req.url, 'topic')
    if (!topic) return send_html(200, 'missing topic', context)
    
    topic = topic.replace(/\W/, '')

    let topic_moderator = await get_moderator(topic, context.db)

    if (context.current_user.user_id !== topic_moderator) return send_html(200, 'non-moderator may not ban', context)

    await query(`insert into topicwatches (topicwatch_name, topicwatch_user_id,         topicwatch_banned_until)
                                   values (              ?,                  ?, date_add(now(), interval 1 day))
                 on duplicate key update topicwatch_banned_until=date_add(now(), interval 1 day)`, [topic, user_id], context.db)

    let bans = await user_topic_bans(user_id, context.db)
    
    return send_html(200, is_user_banned(bans, topic, context.current_user), context)
}

routes.GET.best = async function(context) {

    if ('true' === _GET(context.req.url, 'all')) {
        var sql = `select * from comments left join users on user_id=comment_author where comment_likes > 3
                   order by comment_likes desc limit 40`

        var m = `<h2>best comments of all time</h2>or view the <a href='/best'>last week's</a> best comments<p>`
    }
    else {
        var sql = `select * from comments left join users on user_id=comment_author where comment_likes > 3
                   and comment_date > date_sub(now(), interval 7 day) order by comment_likes desc limit 40`

        var m = `<h2>best comments in the last week</h2>or view the <a href='/best?all=true'>all-time</a> best comments<p>`
    }

    let comments = await query(sql, [], context.db)

    let offset = 0
    comments = comments.map(comment => { comment.row_number = ++offset; return comment })

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            m,
            comment_list(comments, context)
        )
    )

    return send_html(200, content, context)
}

routes.GET.comment_moderation = async function(context) {

    const current_user = context.current_user

    if (!current_user) return die('you must be logged in to moderate comments', context)
    if (!current_user || !current_user.is_moderator_of || !current_user.is_moderator_of.length) return die('you are not moderator of any topic', context)

    let comments = await comments_to_moderate(context)

    let offset = 0
    comments = comments.map(comment => { comment.row_number = ++offset; return comment })

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            h1('comment moderation'),
            comment_list(comments, context)
        )
    )

    return send_html(200, content, context)
}

routes.GET.comments = async function(context) { // show a list of comments by user, or by comment-frequence, or from a search

    let offset  = intval(_GET(context.req.url, 'offset'))
    let comments
    let message = ''

    if (_GET(context.req.url, 'a')) {      // a is author name
        let a   = decodeURIComponent(_GET(context.req.url, 'a').replace(/[^\w %]/, ''))
        let user = await get_user_by_name(a, context.db)
        if (!user) return die(`no such user: ${ a }`, context)
        comments = await get_comment_list_by_author(user, 40, context.db, context.req.url)
        message = `<h2>${a}'s comments</h2>`
    }
    else if (_GET(context.req.url, 'n')) { // n is number of comments per author, so we can see all comments by one-comment authors, for example
        let n   = intval(_GET(context.req.url, 'n'))
        comments = await get_comment_list_by_number(n, offset, 40, context.db)
        message = `<h2>comments by users with ${n} comments</h2>`
    }
    else if (_GET(context.req.url, 's')) { // comment search
        let s   = _GET(context.req.url, 's').replace(/[^\w %]/, '')
        comments = await get_comment_list_by_search(s, offset, 40, context.db)
        message = `<h2>comments that contain "${s}"</h2>`
    }
    else return send_html(200, `invalid request`, context)

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            h1(message),
            comment_pagination(comments, context.req.url),
            comment_list(comments, context),
            comment_search_box()
        )
    )

    return send_html(200, content, context)
}

routes.GET.delete_comment = async function(context) { // delete a comment

    const comment_id = intval(_GET(context.req.url, 'comment_id'))
    const post_id    = intval(_GET(context.req.url, 'post_id'))

    if (!(comment_id && post_id)) return send_html(200, '', context)
    if (!context.current_user)    return send_html(200, '', context)
    if (!valid_nonce(context))    return send_html(200, '', context)

    const topic           = (await get_post(post_id, context.db)).post_topic
    const topic_moderator = intval(await get_moderator(topic, context.db))
    const comment         = await get_row('select * from comments where comment_id=?', [comment_id], context.db)
    const comment_author  = comment.comment_autor
    const user_id         = context.current_user.user_id

    if (!permissions.may_delete_comment(comment, context.current_user)) return send_html(200, '', context)

    await query(`delete from comments where comment_id = ?`, [comment_id, user_id, user_id, user_id], context.db)

    await query(`update users set user_comments=(select count(*) from comments where comment_author = ?) where user_id = ?`,
                [comment_author, comment_author], context.db)

    await reset_latest_comment(post_id, context.db)
    await penalize(comment_author, context)

    // notify admin if comment deleted by a moderator (a level 3 user)
    if (3 === context.current_user.user_level) {
        mail(CONF.admin_email, `comment deleted by ${context.current_user.user_name}`, `${comment.comment_author} said: ${comment.comment_content}`)
    }

    send_html(200, '', context)
}

routes.GET.delete_post = async function(context) { // delete a whole post, but not its comments

    if (!context.current_user) return die('you must be logged in to delete a post', context)
    if (!valid_nonce(context)) return die(invalid_nonce_message(), context)

    var post_id
    if (post_id = intval(_GET(context.req.url, 'post_id'))) {

        let post = await get_post(post_id, context.db)
        if (!post) return die('no such post', context)

        // if it's their own post or if it's admin
        if ((context.current_user.user_id === post.post_author) || (context.current_user.user_level === 4)) {

            let results = await query(`delete from posts where post_id = ?`, [post_id], context.db)

            if (post.post_topic) {
                await update_prev_next(post.post_topic, post.post_prev_in_topic, context.db)
                await update_prev_next(post.post_topic, post.post_next_in_topic, context.db)
            }

            return die(`${results.affectedRows} post deleted`, context)
        }
        else return die('permission to delete post denied', context)
    }
    else return die('need a post_id', context)
}

routes.GET.dislike = async function(context) { // given a comment or post, downvote it

    const user_id = context.current_user ? context.current_user.user_id : await find_or_create_anon(context.db, context.ip)

    if (intval(_GET(context.req.url, 'comment_id'))) {
        const content = await dislike_comment(user_id, context)
        return send_html(200, content, context)
    }
    else if (intval(_GET(context.req.url, 'post_id'))) {
        const content = await dislike_post(user_id, context)
        return send_html(200, content, context)
    }
    else return send_html(200, '', context) // send empty string if no comment_id or post_id
}

routes.GET.edit_comment = async function (context) {

    if (!valid_nonce(context)) return die(invalid_nonce_message(), context)

    let comment_id = intval(_GET(context.req.url, 'c'))
    let comment = await get_row(`select * from comments left join users on user_id=comment_author where comment_id=?`, [comment_id], context.db)

    if (!comment) return send_html(404, `No comment with id "${comment_id}"`, context)
    else {

        let content = html(
            render_query_times(context.res.start_time, context.db.queries),
            head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
            header(context),
            midpage(
                comment_edit_box(comment, context)
            )
        )

        send_html(200, content, context)
    }
}

routes.GET.edit_post = async function (context) {

    if (!valid_nonce(context)) return die(invalid_nonce_message(), context)

    let post_id = intval(_GET(context.req.url, 'p'))
    let post = await get_row(`select * from posts left join users on user_id=post_author where post_id=?`, [post_id], context.db)

    if (!post) return send_html(404, `No post with id "${post_id}"`, context.res, context.db, context.ip)
    else {

        let content = html(
            render_query_times(context.res.start_time, context.db.queries),
            head(CONF.stylesheet, CONF.description, post ? post.post_title : CONF.domain),
            header(context),
            midpage(
                post_form(_GET(context.req.url, 'p'), post)
            )
        )

        send_html(200, content, context)
    }
}

routes.GET.edit_profile = async function(context) {

    if (!context.current_user) return die('please log in to edit your profile', context)

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            profile_form(_GET(context.req.url, 'updated'), context)
        )
    )

    send_html(200, content, context)
}

routes.GET.follow_topic = async function(context) { // get or turn off emails of posts in a topic; can be called as ajax or full page

    let ajax  = intval(_GET(context.req.url, 'ajax'))
    let topic = _GET(context.req.url, 'topic').replace(/\W/, '').toLowerCase()

    if (!topic)                return ajax ? send_html(200, '', context) : die('topic missing', context)
    if (!context.current_user) return ajax ? send_html(200, '', context) : die('must be logged in to follow or unfollow', context)
    if (!valid_nonce(context)) return ajax ? send_html(200, '', context) : die(invalid_nonce_message(), context)

    if (intval(_GET(context.req.url, 'undo'))) {

        await query(`delete from topicwatches where topicwatch_name=? and topicwatch_user_id=?`,
                    [topic, context.current_user.user_id], context.db)
    }
    else {
        await query(`replace into topicwatches set topicwatch_start=now(), topicwatch_name=?, topicwatch_user_id=?`,
                    [topic, context.current_user.user_id], context.db)
    }

    // either way, output follow button with right context and update this user's follow count
    ajax ? send_html(200, follow_topic_button(topic, context.current_user, context.ip), context) : die('Follow status updated', context)
}

routes.GET.follow_user = async function(context) { // get or turn off emails of a user's new posts; can be called as ajax or full page

    let ajax     = intval(_GET(context.req.url, 'ajax'))
    let other_id = intval(_GET(context.req.url, 'other_id'))

    if (!other_id)             return ajax ? send_html(200, '', context) : die('other_id missing', context)
    if (!context.current_user) return ajax ? send_html(200, '', context) : die('must be logged in to follow or unfollow', context)
    if (!valid_nonce(context)) return ajax ? send_html(200, '', context) : die(invalid_nonce_message(), context)

    if (intval(_GET(context.req.url, 'undo'))) {
        await query(`replace into relationships set rel_i_follow=0, rel_self_id=?, rel_other_id=?`,
                    [context.current_user.user_id, other_id], context.db)
    }
    else {
        await query(`replace into relationships set rel_i_follow=unix_timestamp(now()), rel_self_ID=?, rel_other_id=?`,
                    [context.current_user.user_id, other_id], context.db)
    }

    // either way, output follow button with right context and update this user's follow count
    ajax ? send_html(200, follow_user_button(await get_userrow(other_id, context.db)), context) : die('Follow status updated', context)

    await query(`update users set user_followers=(select count(*) from relationships where rel_i_follow > 0 and rel_other_id=?)
                 where user_id=?`, [other_id, other_id], context.db)

    // mail the user who has just been followed
    let u = await get_userrow(other_id, context.db)
    mail(u.user_email, `you have a new follower on ${CONF.domain}`,
        `<a href='https://${CONF.domain}/user/${context.current_user.user_name}'>${context.current_user.user_name}</a> is now following
         you on ${CONF.domain} and will get emails of your new posts`)
}

routes.GET.home = async function(context) {

    var p

    if (p = intval(_GET(context.req.url, 'p'))) return redirect(`/post/${p}`, context, 301) // legacy redirect for cases like /?p=1216301

    let current_user_id = context.current_user ? context.current_user.user_id : 0

    let [curpage, slimit, order, order_by] = which_page(_GET(context.req.url, 'page'), _GET(context.req.url, 'order'))

    // left joins to also get each post's viewing and voting data for the current user if there is one
    let sql = `select sql_calc_found_rows * from posts
               left join postviews on postview_post_id=post_id and postview_user_id= ?
               left join postvotes on postvote_post_id=post_id and postvote_user_id= ?
               left join users     on user_id=post_author where post_modified > date_sub(now(), interval 7 day) and post_approved=1
               ${order_by} limit ${slimit}`

    let posts = await query(sql, [current_user_id, current_user_id], context.db)

    let path = URL.parse(context.req.url).pathname // "pathname" is url path without ? parms, unlike "path"

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, CONF.domain),
        header(context),
        (await comments_to_moderate(context)).length ? `Welcome moderator, there are <a href='/comment_moderation'>comments to moderate</a>` : '',
        midpage(
            tabs(order, '', path),
            post_list(posts, context),
            post_pagination(posts.found_rows, curpage, `&order=${order}`, context.req.url)
        )
    )

    send_html(200, content, context)
}

routes.GET.ignore = async function(context) { // ignore a user

    let other_id = intval(_GET(context.req.url, 'other_id'))

    if (!context.current_user) return send_html(200, '', context)
    if (!valid_nonce(context)) return send_html(200, '', context)

    if (intval(_GET(context.req.url, 'undo'))) {
        await query(`replace into relationships set rel_i_ban=0, rel_self_id=?, rel_other_id=?`,
                    [context.current_user.user_id, other_id], context.db)

        send_html(200, '', context) // make the user disappear from edit_profile page
    }
    else {
        await query(`replace into relationships set rel_i_ban=unix_timestamp(now()), rel_self_ID=?, rel_other_ID=?`,
                    [context.current_user.user_id, other_id], context.db)

        send_html(200, '', context)
    }

    // either way, update this user's ignore count
    await query(`update users set user_bannedby=(select count(*) from relationships where rel_i_ban > 0 and rel_other_id=?)
                 where user_id=?`, [other_id, other_id], context.db)
}

routes.GET.key_login = async function(context) {

    let key      = _GET(context.req.url, 'key')
    let password = get_nonce(Date.now(), context.ip).substring(0, 6)

    var email = await get_var('select user_email from users where user_activation_key = ?', [key], context.db)

    if (email) {
        // erase key so it cannot be used again, and set new password
        await query('update users set user_activation_key=null, user_pass=? where user_activation_key=?', [md5(password), key], context.db)

        login(email, password, context)
    }
    else {

        let content = html(
            render_query_times(context.res.start_time, context.db.queries),
            head(CONF.stylesheet, CONF.description, CONF.domain),
            header(context),
            midpage(
                h1(`Darn, that key has already been used. Please try 'forgot password' if you need to log in.`)
            )
        )

        send_html(200, content, context)
    }
}

routes.GET.liberate = async function(context) { // liberate a comment from comment jail

    const comment_id = intval(_GET(context.req.url, 'comment_id'))

    if (!comment_id)           return send_html(200, '', context)
    if (!context.current_user) return send_html(200, '', context)
    if (!valid_nonce(context)) return send_html(200, '', context)

    await query(`update comments set comment_adhom_when=null where comment_id = ? and (1 = ?)`, [comment_id, context.current_user.user_id], context.db)

    send_html(200, '', context)
}


routes.GET.like = async function(context) { // given a comment or post, upvote it

    var user_id   = context.current_user ? context.current_user.user_id   : await find_or_create_anon(context.db, context.ip)
    var user_name = context.current_user ? context.current_user.user_name : ip2anon(context.ip)

    if (intval(_GET(context.req.url, 'comment_id'))) {
        let content = await like_comment(user_id, user_name, context)
        send_html(200, content, context)
        return await send_comment_like_email(user_name, context)
    }
    else if (intval(_GET(context.req.url, 'post_id'))) {
        let content = await like_post(user_id, context)
        send_html(200, content, context)
        return await send_post_like_email(user_name, context)
    }
    else return send_html(200, '', context) // send empty string if no comment_id or post_id
}

routes.GET.logout = async function(context) {

    var d    = new Date()
    var html = loginprompt(context.login_failed_email)

    // you must use the undocumented "array" feature of res.writeHead to set multiple cookies, because json
    var headers = [
        ['Content-Type'   , 'text/html'                               ],
        ['Expires'        , d.toUTCString()                           ],
        ['Set-Cookie'     , `${ CONF.usercookie }=_; Expires=${d}; Path=/`],
        ['Set-Cookie'     , `${ CONF.pwcookie   }=_; Expires=${d}; Path=/`]
    ] // do not use 'secure' parm with cookie or will be unable to test login in dev, bc dev is http only

    send(200, headers, html, context)
}

routes.GET.new_post = async function(context) {

    if (!context.current_user || !context.current_user.user_id) return die('anonymous users may not create posts', context)

    // if the user is logged in and has posted CONF.max_posts times today, don't let them post more
    var posts_today = await get_var('select count(*) as c from posts where post_author=? and post_date >= curdate()',
                                    [context.current_user.user_id], context.db)

    if (posts_today >= CONF.max_posts || posts_today > context.current_user.user_comments) {
        var content = html(
            render_query_times(context.res.start_time, context.db.queries),
            head(CONF.stylesheet, CONF.description, CONF.domain),
            header(context),
            midpage(
                `You hit your posting limit for today. Please post more tomorrow!`
            )
        )
    }
    else {
        var content = html(
            render_query_times(context.res.start_time, context.db.queries),
            head(CONF.stylesheet, CONF.description, CONF.domain),
            header(context),
            midpage(
                post_form(_GET(context.req.url, 'p'))
            )
        )
    }

    send_html(200, content, context)
}

routes.GET.nuke = async function(context) { // given a user ID, nuke all his posts, comments, and his ID

    let nuke_id = intval(_GET(context.req.url, 'nuke_id'))
    let u = await get_userrow(nuke_id, context.db)

    if (!valid_nonce(context))              return die(invalid_nonce_message(), context)
    if (1 !== context.current_user.user_id) return die('non-admin may not nuke', context)
    if (1 === nuke_id)                      return die('admin cannot nuke himself', context)

    let country = await ip2country(u.user_last_comment_ip, context.db)

    let rows = await query('select distinct comment_post_id from comments where comment_author=?', [nuke_id], context.db)

    for (var i=0; i<rows.length; i++) {
        let row = rows[i]
        await query('delete from comments where comment_post_id=? and comment_author=?', [row.comment_post_id, nuke_id], context.db)
        await reset_latest_comment(row.comment_post_id, context.db)
    }
    await query('delete from posts     where post_author=?',      [nuke_id], context.db)
    await query('delete from postviews where postview_user_id=?', [nuke_id], context.db)
    await query('delete from users     where user_id=?',          [nuke_id], context.db)

    try {
        await query(`insert into nukes (nuke_date, nuke_email, nuke_username,                nuke_ip,  nuke_country) values
                   (now(), ?, ?, ?, ?)`, [u.user_email, u.user_name, u.user_last_comment_ip, country], context.db)
    }
    catch(e) { console.error(e) } // try-catch for case where ip is already in nukes table somehow

    redirect(context.req.headers.referer, context) 
}

routes.GET.old = async function(context) {

    let years_ago = intval(_GET(context.req.url, 'years_ago'))

    let user_id = context.current_user ? context.current_user.user_id : 0
    
    let sql = `select sql_calc_found_rows * from posts
               left join postviews on postview_post_id=post_id and postview_user_id= ?
               left join postvotes on postvote_post_id=post_id and postvote_user_id= ?
               left join users on user_id=post_author
               where post_approved=1 and
               post_date <          date_sub(now(), interval ${years_ago} year) and
               post_date > date_sub(date_sub(now(), interval ${years_ago} year), interval 1 year)
               order by post_date desc limit 40`

    let posts = await query(sql, [user_id, user_id], context.db)
    let s = (years_ago === 1) ? '' : 's'
    
    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            h1(`Posts from ${years_ago} year${s} ago`),
            post_list(posts, context)
        )
    )

    send_html(200, content, context)
}

routes.GET.post = async function(context) { // show a single post and its comments

    let current_user_id = context.current_user ? context.current_user.user_id : 0
    let post_id         = intval(segments(context.req.url)[2]) // get post's db row number from url, eg 47 from /post/47/slug-goes-here

    let c
    if (c = _GET(context.req.url, 'c')) { // permalink to a comment
        let offset = await cid2offset(post_id, c, context.db)
        return redirect(`/post/${post_id}?offset=${offset}#comment-${c}`, context)
    }

    let p = await get_post(post_id, context.db, current_user_id)

    let err = await check_post(p, context)
    if (err) return die(err, context)

    let comments = await post_comment_list(p, context) // pick up the comment list for this post
    p.watchers   = await get_var(`select count(*) as c from postviews where postview_post_id=? and postview_want_email=1`, [post_id], context.db)
    p.post_views++ // increment here for display and in db on next line as record
    await query(`update posts set post_views = ? where post_id=?`, [p.post_views, post_id], context.db)

    if (current_user_id) await update_postview(p, context)
    if (p.post_topic)    await check_topic(p, context)

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, p ? p.post_title : CONF.domain),
        header(context, p.post_topic),
        midpage(
            topic_nav(p),
            post(p, context.ip, context.current_user),
            comment_pagination(comments, context.req.url),
            comment_list(comments, context),
            comment_pagination(comments, context.req.url),
            comment_box(p, context.current_user, context.ip)
        )
    )

    send_html(200, content, context)
}

routes.POST.post_login = async function(context) {
    let post_data = await collect_post_data_and_trim(context)
    login(post_data.email, post_data.password, context)
}

routes.GET.post_moderation = async function (context) {

    if (!context.current_user) return die('you must be logged in to moderate posts', context)

    let posts = await query(`select * from posts left join users on user_id=post_author where post_approved=0 or post_approved is null`, [], context.db)

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            post_list(posts, context)
        )
    )

    send_html(200, content, context)
}

routes.GET.random = async function(context) {

    let rand = await get_var(`select round(rand() * (select count(*) from posts)) as r`, [], context.db)
    let p    = await get_var(`select post_id from posts limit 1 offset ?`, [rand], context.db)

    redirect(`/post/${p}`, context)
}

routes.POST.recoveryemail = async function(context) {

    let post_data = await collect_post_data_and_trim(context)

    let message = await send_login_link(context.ip, context.db, post_data)

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            h1(message)
        )
    )

    send_html(200, content, context)
}

routes.POST.registration = async function(context) {

    let post_data = await collect_post_data_and_trim(context)
    let message = ''

    if (/\W/.test(post_data.user_name))     message = 'Please go back and enter username consisting only of letters'
    if (!valid_email(post_data.user_email)) message = 'Please go back and enter a valid email'

    if (!message) { // no error yet

        if (await get_row('select * from users where user_email = ?', [post_data.user_email], context.db)) {
            message = `That email is already registered. Please use the "forgot password" link above.</a>`
        }
        else {
            if (await get_row('select * from users where user_name = ?', [post_data.user_name], context.db)) {
                message = `That user name is already registered. Please choose a different one.</a>`
            }
            else {
                await query('insert into users set user_registered=now(), ?', post_data, context.db)
                message = await send_login_link(context.ip, context.db, post_data)
            }
        }
    }

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(`<h2>${message}</h2>`)
    )

    send_html(200, content, context)
}

routes.GET.search = async function(context) {

    // if (is_robot()) die('robots may not do searches', context)

    let s = _GET(context.req.url, 's').trim().replace(/[^0-9a-z ]/gi, '') // allow only alphanum and spaces for now
    let us = encodeURI(s)

    if (!s) return die('You searched for nothing. It was found.', context)

    let [curpage, slimit, order, order_by] = which_page(_GET(context.req.url, 'page'), _GET(context.req.url, 'order'))

    // These match() requests require the existence of fulltext index:
    //      create fulltext index post_title_content_index on posts (post_title, post_content)

    let sql = `select sql_calc_found_rows * from posts left join users on user_id=post_author
               where match(post_title, post_content) against ('${s}') ${order_by} limit ${slimit}`

    let posts = await query(sql, [], context.db)

    let path = URL.parse(context.req.url).pathname // "pathNAME" is url path without ? parms, unlike "path"

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            h1(`search results for "${s}"`),
            '<p>',
            post_pagination(posts.found_rows, curpage, `&s=${us}&order=${order}`, context.req.url),
            tabs(order, `&s=${us}`, path),
            post_list(posts, context),
            post_pagination(posts.found_rows, curpage, `&s=${us}&order=${order}`, context.req.url)
        )
    )

    send_html(200, content, context)
}

routes.GET.since = async function(context) { // given a post_id and epoch timestamp, redirect to post's first comment after that timestamp

    // these will die on replace() if p or when is not defined and that's the right thing to do
    let p    = intval(_GET(context.req.url, 'p'))
    let when = intval(_GET(context.req.url, 'when'))

    let c = await get_var(`select comment_id from comments
                               where comment_post_id = ? and comment_approved > 0 and comment_date > from_unixtime(?)
                               order by comment_date limit 1`, [p, when], context.db)

    let offset = await cid2offset(p, c, context.db)
    let post = await get_post(p, context.db)
    redirect(`${post2path(post)}?offset=${offset}#comment-${c}`, context)
}

routes.GET.topic = async function(context) {

    let topic = segments(context.req.url)[2] // like /topic/housing
    if (!topic) return die('no topic given', context)

    let user_id = context.current_user ? context.current_user.user_id : 0
    let [curpage, slimit, order, order_by] = which_page(_GET(context.req.url, 'page'), _GET(context.req.url, 'order'))
    let posts = await query(`select sql_calc_found_rows * from posts
                             left join postviews on postview_post_id=post_id and postview_user_id= ?
                             left join postvotes on postvote_post_id=post_id and postvote_user_id= ?
                             left join users on user_id=post_author
                             where post_topic = ? and post_approved=1 ${order_by} limit ${slimit}`, [user_id, user_id, topic], context.db)
    
    var row = await get_row('select * from users, topics where topic=? and topic_moderator=user_id', [topic], context.db)

    if (row) {
        var moderator_announcement = `<br>Moderator is <a href='/user/${row.user_name}'>${row.user_name}</a>.
            <a href='/post/${row.topic_about_post_id}' title='rules for #${topic}' >Read before posting.</a>`
    }
    else var moderator_announcement = `<br>#${topic} needs a moderator, write <a href='mailto:${ CONF.admin_email }' >${ CONF.admin_email }</a> if
        you\'re interested`

    let path = URL.parse(context.req.url).pathname // "pathNAME" is url path without ? parms, unlike "path"

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context, topic),
        midpage(
            h1('#' + topic),
            follow_topic_button(topic, context.current_user, context.ip),
            moderator_announcement,
            tabs(order, `&topic=${topic}`, path),
            post_list(posts, context),
            post_pagination(posts.found_rows, curpage, `&topic=${topic}&order=${order}`, context.req.url),
            topic_moderation(topic, context.current_user)
        )
    )

    send_html(200, content, context)
}

routes.GET.topics = async function (context) {

    let topics = await query(`select post_topic, count(*) as c from posts
                              where length(post_topic) > 0 group by post_topic having c >=3 order by c desc`, null, context.db)

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            h1('Topics'),
            topic_list(topics)
        )
    )

    send_html(200, content, context)
}

routes.GET.uncivil = async function(context) { // move a comment to comment jail

    let comment_id = intval(_GET(context.req.url, 'c'))

    if (context.current_user && (context.current_user.user_pbias > 3) && valid_nonce(context) && comment_id) {
        await query(`update comments set comment_approved=0, comment_adhom_reporter=?, comment_adhom_when=now() where comment_id = ?`,
                    [context.current_user.user_id, comment_id], context.db)
    }

    mail(CONF.admin_email, 'comment marked uncivil', `<a href='https://${CONF.domain}/comment_moderation'>moderation page</a>`)

    send_html(200, '', context) // blank response in all cases
}

routes.POST.update_profile = async function(context) { // accept data from profile_form

    if (!valid_nonce(context)) return die(invalid_nonce_message(), context)
    if (!context.current_user) return die('must be logged in to update profile', context)

    let post_data = await collect_post_data_and_trim(context)

    if (/\W/.test(post_data.user_name))     return die('Please go back and enter username consisting only of letters', context)
    if (!valid_email(post_data.user_email)) return die('Please go back and enter a valid email', context)

    post_data.user_summonable            = intval(post_data.user_summonable)
    post_data.user_hide_post_list_photos = intval(post_data.user_hide_post_list_photos)

    if (get_external_links(post_data.user_aboutyou).length) return die('Sorry, no external links allowed in profile', context)
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
         context.current_user.user_id], context.db).catch(error => {
            if (error.code.match(/ER_DUP_ENTRY/)) return die(`Sorry, looks like someone already took that email or user name`, context)
            else                                  return die(`Something went wrong with save`, context)
         })

    redirect('/edit_profile?updated=true', context)
}

routes.POST.upload = async function(context) {
    if (!context.current_user) return die('you must be logged in to upload images', context)

    var form = new FORMIDABLE.IncomingForm()
    form.maxFieldsSize = 7 * 1024 * 1024 // max upload is 4MB, but this seems to fail; nginx config will block larger images anyway
    form.maxFields = 1                   // only one image at a time

    form.parse(context.req, async function (err, fields, files) {
        if (err) throw err

        let [url_path, abs_path] = await get_image_path()
        let clean_name           = clean_upload_path(abs_path, files.image.name, context.current_user)

        FS.rename(files.image.path, `${abs_path}/${clean_name}`, async function (err) { // note that files.image.path includes filename at end
            if (err) throw err

            let addendum = ''
            let dims     = await getimagesize(`${abs_path}/${clean_name}`).catch(error => { addendum = `"${error}"` })
            if (!dims) return die('failed to find image dimensions', context)

            if (context.req.headers.referer.match(/edit_profile/)) { // uploading user icon
                dims = await resize_image(`${abs_path}/${clean_name}`, 80)    // limit max width to 80 px
                await update_icon(`${url_path}/${clean_name}`, dims, context)
                return redirect('/edit_profile', context)
            }
            else { // uploading image link to post or comment text area
                if (dims[0] > 600) dims = await resize_image(`${abs_path}/${clean_name}`, 600)   // limit max width to 600 px
                addendum = `"<img src='${url_path}/${clean_name}' width='${dims[0]}' height='${dims[1]}' >"`

                let content = `
                    <html>
                        <script>
                            var textarea = parent.document.getElementById('ta');
                            textarea.value = textarea.value + ${addendum};
                        </script>
                    </html>`

                send_html(200, content, context)
            }
        })
    })
}

routes.GET.user = async function(context) {

    let current_user_id = context.current_user ? context.current_user.user_id : 0
    let [curpage, slimit, order, order_by] = which_page(_GET(context.req.url, 'page'), _GET(context.req.url, 'order'))
    let user_name = decodeURIComponent(segments(context.req.url)[2]).replace(/[^\w._ -]/g, '') // like /user/Patrick
    let u = await get_row(`select * from users where user_name=?`, [user_name], context.db)

    if (!u) return die(`no such user: ${user_name}`, context)

    // left joins to also get each post's viewing and voting data for the current user if there is one
    let sql = `select sql_calc_found_rows * from posts
               left join postviews on postview_post_id=post_id and postview_user_id= ?
               left join postvotes on postvote_post_id=post_id and postvote_user_id= ?
               left join users     on user_id=post_author
               where post_approved=1 and user_id=?
               ${order_by} limit ${slimit}`

    let posts = await query(sql, [current_user_id, current_user_id, u.user_id], context.db)

    u.bans = await user_topic_bans(u.user_id, context.db)

    let path = URL.parse(context.req.url).pathname // "pathNAME" is url path without ? parms, unlike "path"

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            render_user_info(u, context.current_user, context.ip),
            tabs(order, '', path),
            post_list(posts, context),
            post_pagination(posts.found_rows, curpage, `&order=${order}`, context.req.url),
            admin_user(u, context.current_user, context.ip)
        )
    )

    send_html(200, content, context)
}

routes.GET.users = async function(context) {

    const d = ['asc', 'desc'].includes(_GET(context.req.url, 'd')) ? _GET(context.req.url, 'd') : 'desc'

    const ob = ['user_bannedby',
                'user_banning',
                'user_comments',
                'user_dislikes',
                'user_followers',
                'user_friends',
                'user_likes',
                'user_name',
                'user_posts',
                'user_registered'].includes(_GET(context.req.url, 'ob')) ? _GET(context.req.url, 'ob') : 'user_comments' // order by

    let offset = intval(_GET(context.req.url, 'offset')) || 0
    let message = ''
    let users

    if      (_GET(context.req.url, 'unrequited'))  [message, users] = await get_unrequited( context, d, ob, offset)
    else if (_GET(context.req.url, 'followersof')) [message, users] = await get_followersof(context, d, ob, offset)
    else if (_GET(context.req.url, 'following'))   [message, users] = await get_following(  context, d, ob, offset)
    else if (_GET(context.req.url, 'friendsof'))   [message, users] = await get_friendsof(  context, d, ob, offset)
    else if (_GET(context.req.url, 'user_name'))   [message, users] = await get_user_name(  context, d, ob, offset)
    else                                           [message, users] = await get_users(      context, d, ob, offset)

    let next_page = context.req.url.match(/offset=/) ? context.req.url.replace(/offset=\d+/, `offset=${offset + 40}`) :
        context.req.url.match(/\?/) ? context.req.url + '&offset=40' : context.req.url + '?offset=40'

    let content = html(
        render_query_times(context.res.start_time, context.db.queries),
        head(CONF.stylesheet, CONF.description, context.post ? context.post.post_title : CONF.domain),
        header(context),
        midpage(
            h1(message),
            `<p><a href='${next_page}'>next page &raquo;</a><p>`,
            user_list(users, _GET(context.req.url, 'd')),
            `<hr><a href='${next_page}'>next page &raquo;</a>`
        )
    )

    send_html(200, content, context)
}

routes.GET.watch = async function(context) { // toggle a watch from a post

    let post_id = intval(_GET(context.req.url, 'post_id'))

    if (!context.current_user) return send_html(200, '', context)
    if (!valid_nonce(context)) return send_html(200, '', context)
    if (!post_id)              return send_html(200, '', context)

    let postview_want_email = await get_var(`select postview_want_email from postviews
                                             where postview_user_id=? and postview_post_id=?`,
                                             [context.current_user.user_id, post_id], context.db)

    if (postview_want_email) var want_email = 0 // invert
    else                     var want_email = 1

    await query(`insert into postviews (postview_user_id, postview_post_id, postview_want_email) values (?, ?, ?)
                 on duplicate key update postview_want_email=?`,
                [context.current_user.user_id, post_id, want_email, want_email], context.db)

    send_html(200, render_watch_indicator(want_email), context)
}

// from here to end are only html components
// * all pure synchronous functions: no reading outside parms, no modification of parms, no side effects, can be replaced with ret value
// * mostly just take (data, context) objects
// * all return html
// * all html without unique html tag has id which includes name of the function which generated it

function html(query_times, head, ...args) {
    return `<!DOCTYPE html><html lang='en'>
    ${ query_times }
    ${ head }
    <body>
        <div class='container' >
        ${ args.join('') }
        ${ footer() }
        </div>
    </body>
    <script async src='/jquery.min.js'></script>
    </html>`
}

function head(stylesheet, description, title) {
    return `<head>
    <link href='/${ stylesheet }' rel='stylesheet' type='text/css' />
    <link rel='icon' href='/favicon.ico' />
    <meta charset='utf-8' />
    <meta name='description' content='${ description }' />
    <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no' />
    <title>${ title }</title>
    ${client_side_js()}
    </head>`
}

function h1(message) {
    return `<h1 style='display: inline;' id='h1' >${ message }</h1>`
}

function post_pagination(post_count, curpage, extra, url) {

    if (!url) return

    let links    = `<span id='post_pagination'>`
    let nextpage = curpage + 1
    let pages    = Math.floor( (post_count + 20) / 20)
    let path     = URL.parse(url).pathname
    let prevpage = curpage - 1

    if (curpage > 1) links = links + `<a href='${path}?page=${prevpage}${extra}'>&laquo; previous</a> &nbsp;`

    links = links + ` page ${curpage} of ${pages} `

    if (curpage < pages) links = links + `&nbsp; <a href='${path}?page=${nextpage}${extra}'>next &raquo;</a>`

    links = links + '</span>'

    return links
}

function footer() {
    return `
    <div id='footer' >
        <center>
            <a href='/users'>users</a> &nbsp;
            <a href='/about'>about</a> &nbsp;
            <a href='/post/1302130/2017-01-28-patnet-improvement-suggestions'>suggestions</a> &nbsp;
            <a href='https://github.com/killelea/node.${CONF.domain}'>source code</a> &nbsp;
            <a href='mailto:${ CONF.admin_email }' >contact</a> &nbsp;
            <br>
            <a href='/topics'>topics</a> &nbsp;
            <a href='/best'>best comments</a> &nbsp;
            <a href='/old?years_ago=1'>old posts by year</a> &nbsp;
            <br>
            <form method='get' action='/search' ><input name='s' type='text' placeholder='search...' size='20' ></form>
            <p>
        </center>
        ${nav()}
        ${like_dislike()}
    </div>`
}

function nav() {
    return `
    <div class='fixed' id='nav' >
        <a href='#' title='top of page' >top</a> &nbsp; <a href='#footer' title='bottom of page' >bottom</a> &nbsp; <a href='/' title='home page' >home</a>
    </div>`
}

function like_dislike() {
    return `
    <script id='like_dislike' >
        function like(content) {
            $.get( "/like?comment_id="+content.split("_")[1], function(data) { document.getElementById(content).innerHTML = data; });
        }
        function dislike(content) {
            $.get( "/dislike?comment_id="+content.split("_")[1], function(data) { document.getElementById(content).innerHTML = data; });
        }
        function postlike(content) { // For whole post instead of just one comment.
            $.get( "/like?post_id="+content.split("_")[1]+"_up", function(data) { document.getElementById(content).innerHTML = data; });
        }
        function postdislike(content) { // For whole post instead of just one comment.
            $.get( "/dislike?post_id="+content.split("_")[1]+"_down", function(data) { document.getElementById(content).innerHTML = data; });
        }
    </script>`
}

function follow_topic_button(t, current_user, ip) { // t is the topic to follow, a \w+ string

    let b = `<button type='button' class='btn btn-default btn-xs' title='get emails of new posts in ${t}' >follow ${t}</button>`

    var unfollow_topic_link = `
        <span id='unfollow_topic_link' >following
            <sup>
            <a href='#'
               title='unfollow ${t}'
               onclick="$.get('/follow_topic?topic=${t}&undo=1&${create_nonce_parms(ip)}&ajax=1',
                function() { document.getElementById('follow').innerHTML = document.getElementById('follow_topic_link').innerHTML }); return false" >x</a>
            </sup>
        </span>`

    var follow_topic_link = `
        <span id='follow_topic_link'>
            <a href='#'
               title='get emails of new posts in ${t}'
               onclick="$.get('/follow_topic?topic=${t}&${create_nonce_parms(ip)}&ajax=1',
                function() { document.getElementById('follow').innerHTML = document.getElementById('unfollow_topic_link').innerHTML }); return false" >${b}</a>
        </span>`

    if (current_user
     && current_user.topics
     && current_user.topics.includes(t)) {
        var follow = `<span id='follow' >${unfollow_topic_link}</span>`
    }
    else {
        var follow = `<span id='follow' >${follow_topic_link}</span>`
    }

    return `<span style='display: none;' id='follow_topic_button' > ${follow_topic_link} ${unfollow_topic_link} </span> ${follow}`
}

function header(context, topic) {

    const current_user       = context.current_user
    const header_data        = context.header_data
    const login_failed_email = context.login_failed_email

    return `<div class='comment' id='header' >
        <div style='float:right' >${ icon_or_loginprompt(current_user, login_failed_email) }</div>
        <a href='/' ><h1 class='sitename' title='back to home page' >${ CONF.domain }</h1></a>
        <br>
        ${ CONF.description + '<br>' + brag(header_data) + '</font><br>' + new_post_button() }
        </div>`
}

function comment_search_box() {
    return `<form name='searchform' action='/comments' method='get' id='comment_search_box' > 
      <fieldset> 
      <input type='text'   name='s'      value='' size='17' /> 
      <input type='hidden' name='offset' value='0' /> 
      <input type='submit'               value='Search comments &raquo;' />  
      </fieldset> 
    </form>`
}

function comment_links(c, context, offset) { // return links to be placed above the comment

    const current_user = context.current_user
    const ip           = context.ip
    const req          = context.req

    if (!req.url) return

    const liketext    = c.commentvote_up   ? 'you like this'    : '&#8593;&nbsp;like'
    const disliketext = c.commentvote_down ? 'you dislike this' : '&#8595;&nbsp;dislike'

    let links = []

    links.push(`<a href='#' onclick="if (confirm('Really ignore ${c.user_name}?')) { $.get('/ignore?other_id=${ c.user_id }&${create_nonce_parms(ip)}', function() { $('#comment-${ c.comment_id }').remove() }); return false}; return false" title='ignore ${c.user_name}' >ignore (${c.user_bannedby})</a>`)
    links.push(get_permalink(c, current_user ? current_user.user_timezone : 'America/Los_Angeles'))
    links.push(`<a href='#' id='like_${c.comment_id}' onclick="like('like_${c.comment_id}');return false">${liketext} (${c.comment_likes})</a>`)
    links.push(`<a href='#' id='dislike_${c.comment_id}' onclick="dislike('dislike_${c.comment_id}');return false">${disliketext} (${c.comment_dislikes})</a>`)
    links.push(contextual_link(c, current_user, req.url, ip))
    links.push(`<a href="#commentform"
                    onclick="addquote('${c.comment_post_id}', '${offset}', '${c.comment_id}', '${c.user_name}'); return false;"
                    title="select some text then click this to quote" >quote</a>`)
    links.push(get_edit_link(c, current_user, ip))
    links.push(get_del_link(c, current_user, ip))
    links.push(get_nuke_link(c, current_user, ip, req))

    return links
}

function format_comment(c, context, comments, offset) {

    const current_user = context.current_user

    if (current_user) {
        if (current_user.relationships[c.user_id] &&
            current_user.relationships[c.user_id].rel_i_ban) var hide = `style='display: none'`
        else var hide = ''
    }

    c.user_name = c.user_name || 'anonymous' // so we don't display 'null' in case the comment is anonymous

    // for the last comment in the whole result set (not just last on this page) add an id="last"
    // comments may not be defined, for example when we just added one comment
    if (comments)
        var last = (c.row_number === comments.found_rows) ? `<span id='last'></span>` : ''
    else
        var last = ''

    const links = comment_links(c, context, offset)

    return `${last}<div class="comment" id="comment-${c.comment_id}" ${hide} >
    <font size=-1 >
        ${c.row_number || ''}
        &nbsp;
        ${render_user_icon(c, 0.4, `'align='left' hspace='5' vspace='2'`)}
        ${c.user_name ? `<a href='/user/${c.user_name}'>${c.user_name}</a>` : 'anonymous'}
        &nbsp;
        ${links.join(' &nbsp; ')}
    </font><p><div id='comment-${c.comment_id}-text'>${ c.comment_content }</div></div>`
}

function contextual_link(c, current_user, url, ip) { // a link in the comment header that varies by comment context, jail, moderation, etc

    if (!current_user) return ''
    if (!url)          return ''

    if (URL.parse(url).pathname.match(/jail/) && (current_user.user_level === 4)) {
        let retval = c.reporter_name ? `jailed by <a href='/user/${c.reporter_name}'>${c.reporter_name}</a>` : ''

        if (current_user.user_level === 4) retval += ` &nbsp; <a href='#' onclick="$.get('/liberate?comment_id=${c.comment_id}&${create_nonce_parms(ip)}',
                            function() { $('#comment-${ c.comment_id }').remove() }); return false" >liberate</a>`

        return retval
    }
    
    if (URL.parse(url).pathname.match(/comment_moderation/) && (current_user.user_level === 4)) {
        return `<a href='#'
                   onclick="$.get('/approve_comment?comment_id=${ c.comment_id }&${create_nonce_parms(ip)}',
                            function() { $('#comment-${ c.comment_id }').remove() }); return false"
                >approve</a>`
    }

    if (current_user.user_pbias >= 3 || current_user.user_level === 4) {
        return `<a href='#'
                   title='attacks person, not point'
                   onclick="if (confirm('Really mark as uncivil?')) {
                                $.get('/uncivil?c=${ c.comment_id }&${create_nonce_parms(ip)}', function() { $('#comment-${ c.comment_id }').remove() });
                                return false
                            }"
                >uncivil</a>`
    }
    else return ''
}

function render_query_times(start_time, queries) {
    var db_total_ms = 0

    var queries = queries.sortByProp('ms').map( (item) => {
        db_total_ms += item.ms
        return `${ item.ms }ms ${ item.sql }`
    }).join('\n')

    return `<span id='render_query_times' >
                <!-- ${'\n' + queries + '\n'}\n${db_total_ms} ms db\n${Date.now() - start_time} ms total time -->
            </span>`
}

function client_side_js() {
    return `<script>
    function addquote(post_id, offset, comment_id, author) {
        var textarea = document.forms['commentform'].elements['ta'];
        var theSelection = '';

        if (comment_id > 0) var comment_link = '<a href="/post/' + post_id + '&offset=' + offset + '#comment-' + comment_id + '">' + author + ' says</a>';
        else                var comment_link = '<a href="/post/' + post_id                                                  + '">' + author + ' says</a>';

        if (theSelection = getHTMLOfSelection()) { // user manually selected something
            if (s = sessionStorage.getItem('tripleclickselect')) { // override tripleclick selection to avoid getting extra html elements
                theSelection = s.trim(); // trim bc tripleclick appends useless whitespace
                sessionStorage.removeItem('tripleclickselect'); // so we don't keep using it by mistake
            }
        }
        else theSelection = document.getElementById('comment-' + comment_id + '-text').innerHTML;
        // either we are on mobile (no selection possible) or the user did not select any text; whole comment, or post when comment_id === 0
        if (theSelection.length > 1024) var theSelection = theSelection.substring(0, 1000) + '...'; // might mangle tags
        textarea.value = textarea.value + comment_link + '<br><blockquote>' + theSelection + '</blockquote>';
        textarea.focus();
        return;
    }

    window.addEventListener('click', function (evt) {
        if (evt.detail === 3) {
            sessionStorage.setItem('tripleclickselect', window.getSelection());
            setTimeout(function() { sessionStorage.removeItem('tripleclickselect'); }, 10000); // delete after 10s so it dn confuse them later
        }
    });

    function getHTMLOfSelection () {
      if (!window.getSelection) return '';
      var selection = window.getSelection();
      if (selection.rangeCount <= 0) return ''
      var range = selection.getRangeAt(0);
      var clonedSelection = range.cloneContents();
      var div = document.createElement('div');
      div.appendChild(clonedSelection);
      return div.innerHTML;
    }
    </script>`
}

function render_watch_indicator(want_email) {
    return want_email ? `<img src='/content/openeye.png' > unwatch` : `<img src='/content/closedeye.png' > watch`
}

function user_search_box() {
    return `
    <form name='input' action='/users' method='get' >
        <input type='text' size=40 maxlength=80 name='user_name' autofocus />
        <input type='submit' value='User Search' />
    </form>`
}

function user_list(users, d) {

    d = d ? d.replace(/[^adesc]/, '').substring(0,4)  : 'desc' // asc or desc
    let i = (d === 'desc') ? 'asc' : 'desc'                    // invert asc or desc

    let header = `<div id='user_list' >${user_search_box()} <p>
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

    if (users.length) {
        var formatted = users.map( (u) => {
            return `<tr>
                <td >${render_user_icon(u)}</td>
                <td align=left >${user_link(u)}</td>
                <td align=left >${render_date(u.user_registered)}</td>
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

    return header + result + '</table></div>'
}

function render_user_icon(u, scale=1, img_parms='') { // clickable icon for this user if they have icon

    var user_icon_width  = Math.round(u.user_icon_width  * scale)
    var user_icon_height = Math.round(u.user_icon_height * scale)

    return u.user_icon ?
            `<a href='/user/${ u.user_name }' id='render_user_icon' >
                <img src='${u.user_icon}' width='${user_icon_width}' height='${user_icon_height}' ${img_parms} >
             </a>` : ''
}

function user_link(u) {
    return `<a href='/user/${ u.user_name }' id='user_link' >${ u.user_name }</a>`
}

function follow_user_button(u, current_user, ip) { // u is the user to follow, a row from users table

    let b = `<button type="button" class="btn btn-default btn-xs" title="get emails of new posts by ${u.user_name}" >follow ${u.user_name}</button>`

    var unfollow_user_link = `<span id='unfollow_user_link' >following<sup>
                         <a href='#' onclick="$.get('/follow_user?other_id=${u.user_id}&undo=1&${create_nonce_parms(ip)}&ajax=1',
                         function() { document.getElementById('follow').innerHTML = document.getElementById('follow_user_link').innerHTML }); return false" >x</a></sup></span>`

    var follow_user_link = `<span id='follow_user_link' >
                       <a href='#' title='hide all posts and comments by ${u.user_name}'
                       onclick="$.get('/follow_user?other_id=${u.user_id}&${create_nonce_parms(ip)}&ajax=1',
                       function() { document.getElementById('follow').innerHTML = document.getElementById('unfollow_user_link').innerHTML }); return false" >${b}</a></span>`

    if (current_user
     && current_user.relationships
     && current_user.relationships[u.user_id]
     && current_user.relationships[u.user_id].rel_i_follow) {
        var follow = `<span id='follow' >${unfollow_user_link}</span>`
    }
    else {
        var follow = `<span id='follow' >${follow_user_link}</span>`
    }

    return `<span style='display: none;' > ${follow_user_link} ${unfollow_user_link} </span> ${follow}`
}

function render_ban_link(user, topic, current_user, ip) {

    if (!current_user) return ''

    var id=`ban_${user.user_id}_from_${topic}`

    var ban_message = is_user_banned(user.bans, topic, current_user)

    if (ban_message) return ban_message

    return (current_user.user_level === 4 || current_user.is_moderator_of.includes(topic)) ?
        `<a href='#'
            id='${id}'
            onclick="if (confirm('Ban ${user.user_name} from ${topic} for a day?')) {
                         $.get(
                             '/ban_from_topic?user_id=${user.user_id}&topic=${topic}&${create_nonce_parms(ip)}',
                             function(response) { $('#${id}').html(response) }
                         );
                         return false;
                     }";
         >ban ${user.user_name} from ${topic} for a day</a>` : ''
}

function render_unread_comments_icon(post, current_user) { // return the blinky icon if there are unread comments in a post

    if (!current_user) return ''

    // if post.post_latest_commenter_id is an ignored user, just return
    // prevents user from seeing blinky for ignored users, but unfortunately also prevents blinky for wanted unread comments before that
    if (current_user
     && current_user.relationships
     && current_user.relationships[post.post_latest_commenter_id]
     && current_user.relationships[post.post_latest_commenter_id].rel_i_ban) return ''

    if (!post.postview_last_view)
        return `<a href='${post2path(post)}' ><img src='/content/unread_post.gif' width='45' height='16' title='You never read this one' ></a>`

    // if post_modified > last time they viewed this post, then give them a link to earliest unread comment
    let last_viewed = Date.parse(post.postview_last_view) / 1000
    let modified    = Date.parse(post.post_modified) / 1000

    if (modified > last_viewed) {

        let unread = `<a href='/since?p=${post.post_id}&when=${last_viewed}' ><img src='/content/unread_comments.gif' width='19' height='18' title='View unread comments'></a>`

        return unread
    }
    else return ''
}

function render_upload_form() {

    return `
    <form enctype='multipart/form-data' id='upload-file' method='post' target='upload_target' action='/upload' >
        <input type='file'   id='upload'   name='image' class='form' /> 
        <input type='submit' value='Include Image' class='form' />
    </form>
    <iframe id='upload_target' name='upload_target' src='' style='display: none;' ></iframe>` // for uploading a bit of js to insert the img link
}

function topic_nav(post) {

    if (post && post.post_topic) {
        let prev_link = post.post_prev_in_topic ? `&laquo; <a href='/post/${post.post_prev_in_topic}'>prev</a>  &nbsp;` : ''
        let next_link = post.post_next_in_topic ? `&nbsp;  <a href='/post/${post.post_next_in_topic}'>next</a> &raquo;` : ''

        return `<b>${prev_link} ${post.post_topic} ${next_link}</b>`
    }
    else return ``
}

function admin_user(u, current_user, ip) { // links to administer a user

    if (!current_user)                              return ``
    if (current_user && current_user.user_level !== 4) return ``

    return `<hr>
        <a href='https://whatismyipaddress.com/ip/${u.user_last_comment_ip}'>geolocate</a> &nbsp;
        <a href='/user/${u.user_name}?become=1&${create_nonce_parms(ip)}' >become ${u.user_name}</a> &nbsp;
        <a href='/nuke?nuke_id=${u.user_id}&${create_nonce_parms(ip)}' onClick='return confirm("Really?")' >nuke</a> &nbsp;
        <hr>`
}

function arrowbox(post) { // output html for vote up/down arrows; takes a post left joined on user's votes for that post

    var upgrey   = post.postvote_up   ? `style='color: grey; pointer-events: none;'` : ``
    var downgrey = post.postvote_down ? `style='color: grey; pointer-events: none;'` : ``

    var likelink    = `href='#' ${upgrey}   onclick="postlike('post_${post.post_id}_up'); return false;"`
    var dislikelink = `href='#' ${downgrey} onclick="postdislike('post_${post.post_id}_down');return false;"`

    return `<div class='arrowbox' >
            <a ${likelink}    title='${post.post_likes} upvotes'      >&#9650;</a><br>
            <span id='post_${post.post_id}_up' />${post.post_likes}</span><br>
            <span id='post_${post.post_id}_down' />${post.post_dislikes}</span><br>
            <a ${dislikelink} title='${post.post_dislikes} downvotes' >&#9660;</a>
            </div>`
}

function topic_moderation(topic, current_user) {

    if (!current_user || !current_user.is_moderator_of) return ''
    if (!current_user.is_moderator_of.includes(topic))  return ''

    return `<hr id='moderation' >
        <h2>Welcome ${current_user.user_name}, moderator of ${topic}!</h2>
        set or edit "About ${topic}"<br>
        posts waiting for moderation<br>
        comments waiting for moderation<br>
        review jailed comments<br>
        user blacklist by ip or username<br>
        user whitelist<br>
        set background image<br>
        set color<br>
        set donation link<br>`
}

function topic_list(topics) {
    return topics ? topics.map(item => `<a href='/topic/${ item.post_topic }'>#${ item.post_topic }</a>`).join(' ') : ''
}

function top_topics() {
    return `
        <a href='/topic/housing'>#housing</a> 
        <a href='/topic/investing'>#investing</a> 
        <a href='/topic/politics'>#politics</a> 
        <a href='/random'>#random</a> <a href='/topics/'>more&raquo;</a>`
}

function tabs(order, extra='', path) {

    if (!path) return

    let selected_tab = []
    selected_tab['active']   = ''
    selected_tab['comments'] = ''
    selected_tab['likes']    = ''
    selected_tab['new']      = ''
    selected_tab[order]      = `class='active'` // default is active

    return `<ul class='nav nav-tabs'>
        <li ${selected_tab['active']}   > <a href='${path}?order=active${extra}'   title='most recent comments'       >active</a></li>
        <li ${selected_tab['comments']} > <a href='${path}?order=comments${extra}' title='most comments in last week' >comments</a></li>
        <li ${selected_tab['likes']}    > <a href='${path}?order=likes${extra}'    title='most likes in last week'    >likes</a></li>
        <li ${selected_tab['new']}      > <a href='${path}?order=new${extra}'      title='newest'                     >new</a></li>
        </ul>`
}

function brag(header_data) {

    const online_list = header_data.onlines.map(u => `<a href='/user/${u.online_username}'>${u.online_username}</a>`).join(', ')

    return `${ header_data.comments.number_format() } comments by
            <a href='/users'>${ header_data.tot.number_format() } users</a>;
            ${ online_list } ${online_list.length ? 'and' : ''} ${ header_data.lurkers } lurker${ header_data.lurkers === 1 ? '' : 's'} online now`
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
        <script>document.getElementById('user_name').focus();</script>
    </div>`
}

function get_permalink(c, utz) {
    return `<a href='/post/${c.comment_post_id}/?c=${c.comment_id}' title='permalink' >${render_date(c.comment_date, utz)}</a>`
}

permissions.may_delete_comment = function (comment, current_user) {

    if (!current_user) return false

    return ((current_user.user_id    === comment.comment_author) || // it's your own comment
            (current_user.user_level === 4)                      || // it's the site admin
            (current_user.user_level === 3 && comment.comment_approved == 0 && comment.comment_adhom_reporter != current_user.user_id))
            // level 3 users can delete comments from moderation, unless they put it in moderation themselves
     ? true : false
}

function get_del_link(comment, current_user, ip) {
    return permissions.may_delete_comment(comment, current_user)
           ?
           `<a href='#' onclick="if (confirm('Really delete?')) { $.get('/delete_comment?comment_id=${ comment.comment_id }&post_id=${ comment.comment_post_id }&${create_nonce_parms(ip)}', function() { $('#comment-${ comment.comment_id }').remove() }); return false}">delete</a>`
           :
           ''
}

function profile_form(updated, context) {

    let u = context.current_user
    if (!u) return die('please log in to edit your profile', context)

    let message = updated ? `<h3><font color='green'>your profile has been updated</font></h3>` : ''
    let ret = `<h1>edit profile</h1>${message}
    <table>
    <tr>
    <td>${render_user_icon(u)} &nbsp; </td>
    <td>
        <div style='margin: 0px; padding: 5px; border: 1px solid #ddd; background-color: #f5f5f5; display: inline-block;' >
            <form enctype='multipart/form-data' id='upload-file' method='post' action='upload'>
                Upload any size image to represent you (gif, jpg, png, bmp)<br>
                Image will automatically be resized after upload<p>
                <input type='file'   id='upload' name='image' class='form' />
                <input type='submit' value='Upload &raquo;' class='form' />
            </form>
        </div>
    </td></tr></table><p>
    <form name='profile' action='update_profile?${create_nonce_parms(context.ip)}' method='post'>
    <input type='text' name='user_name'  placeholder='user_name' size='25' value='${ u.user_name }'  maxlength='30'  /> user name<p>
    <input type='text' name='user_email' placeholder='email'     size='25' value='${ u.user_email }' maxlength='100' /> email<p>
    <input type='checkbox' name='user_summonable' value='1' ${ u.user_summonable ? 'checked' : '' } >
        Get emails of comments which have '@${ u.user_name }' and get emails of 'likes' of your comments <br>
    <input type='checkbox' name='user_hide_post_list_photos' value='1' ${ u.user_hide_post_list_photos ? 'checked' : '' } >Hide images on post lists
    <h2>about you</h2>
    <textarea class='form-control' rows='3' name='user_aboutyou' >${u.user_aboutyou || ''}</textarea><br>
    <input type='submit' class='btn btn-success btn-sm' value='Save' />
    </form><p><h3>ignored users</h3>(click to unignore that user)<br>`

    let ignored_users = u.relationships ? u.relationships.filter(rel => rel).filter(rel => rel.rel_i_ban) : null
    
    if (ignored_users && ignored_users.length)
        ret += ignored_users.map(u => `<a href='#' onclick="$.get('/ignore?other_id=${u.user_id}&undo=1&${create_nonce_parms(context.ip)}',
         function() { $('#user-${ u.user_id }').remove() }); return false" id='user-${u.user_id}' >${u.user_name}</a><br>`).join('')
    else
        ret += 'none'

    return ret
}

function render_user_info(u, current_user, ip) {
    const img = render_user_icon(u)

    const edit_or_logout = (current_user && u.user_id === current_user.user_id) ?
        `<div style='float:right'><b><a href='/edit_profile'>edit profile</a> &nbsp; 
           <a href='#' onclick="$.get('/logout', function(data) { $('#status').html(data) });return false">logout</a></b>
        </div><div style='clear: both;'></div>` : ''

    const unignore_link = `<span id='unignore_link' >ignoring ${u.user_name}<sup>
                         <a href='#' onclick="$.get('/ignore?other_id=${u.user_id}&undo=1&${create_nonce_parms(ip)}',
        function() { document.getElementById('ignore').innerHTML = document.getElementById('ignore_link').innerHTML }); return false" >x</a></sup></span>`

    const ignore_link = `<span id='ignore_link' >
                       <a href='#' title='hide all posts and comments by ${u.user_name}'
                       onclick="$.get('/ignore?other_id=${u.user_id}&${create_nonce_parms(ip)}',
        function() { document.getElementById('ignore').innerHTML = document.getElementById('unignore_link').innerHTML }); return false" >ignore</a></span>`

    if (current_user
     && current_user.relationships
     && current_user.relationships[u.user_id]
     && current_user.relationships[u.user_id].rel_i_ban) {
        var ignore = `<span id='ignore' >${unignore_link}</span>`
    }
    else var ignore = `<span id='ignore' >${ignore_link}</span>`

    var ban_links = ''
    if (current_user && current_user.is_moderator_of.length) {
        ban_links = current_user.is_moderator_of.map(topic => render_ban_link(u, topic, current_user, ip)).join('<br>')
    }

    return `${edit_or_logout}
            <center><a href='/user/${u.user_name}' >${ img }</a><h2>${u.user_name}</h2>
                ${u.user_aboutyou || ''}
                <p>joined ${ render_date(u.user_registered) } &nbsp;
                ${u.user_country ? u.user_country : ''}
                ${u.user_posts.number_format()} posts &nbsp;
                <a href='/comments?a=${encodeURI(u.user_name)}'>${ u.user_comments.number_format() } comments</a> &nbsp;
                ${follow_user_button(u, current_user, ip)} &nbsp;
                <span style='display: none;' > ${ignore_link} ${unignore_link} </span>${ignore}
                <p>${ban_links}
            </center>`
}

function post(post, ip, current_user) { // format a single post for display

    let uncivil       = ''
    let arrowbox_html = arrowbox(post)
    let icon          = render_user_icon(post, 1, `align='left' hspace='5' vspace='2'`)
    let link          = post_link(post)
    let nonce_parms   = create_nonce_parms(ip)

    if (current_user && current_user.user_pbias >= 3) {

        if (!post.post_title.match(/thunderdome/)) {
            let confirm_uncivil = `onClick="return confirm('Really mark as uncivil?')"`
            uncivil = ` &nbsp; <a href='/uncivil?p=${post.post_id}&${nonce_parms}' ${confirm_uncivil} title='attacks person, not point' >uncivil</a> &nbsp;` 
        }
    }

    let watcheye = `<a href='#' id='watch' onclick="$.get('/watch?post_id=${post.post_id}&${nonce_parms}', function(data) {
        document.getElementById('watch').innerHTML = data; });
        return false" title='comments by email'>${render_watch_indicator(post.postview_want_email)}</a>`

    let edit_link = (current_user && ((current_user.user_id === post.post_author) || (current_user.user_level >= 4)) ) ?
        `<a href='/edit_post?p=${post.post_id}&${nonce_parms}'>edit</a> ` : ''

    let delete_link = (current_user && ((current_user.user_id === post.post_author && !post.post_comments) || (current_user.user_level >= 4))) ?
        `<a href='/delete_post?post_id=${post.post_id}&${nonce_parms}' onClick="return confirm('Really delete?')" id='delete_post' >delete</a> ` : ''

    post.user_name = post.user_name || 'anonymous' // so we don't display 'null' in case the post is anonymous

    var utz = current_user ? current_user.user_timezone : 'America/Los_Angeles'

    return `<div class='comment' >${arrowbox_html} ${icon} <h2 style='display:inline' >${ link }</h2>
            <p>By ${user_link(post)} ${follow_user_button(post, current_user, ip)} &nbsp; ${render_date(post.post_date, utz)} ${uncivil}
            ${post.post_views.number_format()} views &nbsp; ${post.post_comments.number_format()} comments &nbsp;
            ${watcheye} &nbsp;
            <a href="#commentform" onclick="addquote( '${post.post_id}', '0', '0', '${post.user_name}' ); return false;"
               title="Select some text then click this to quote" >quote</a> &nbsp;
            &nbsp; ${share_post(post)} &nbsp; ${edit_link} &nbsp; ${delete_link}
            <p><hr><div class="entry" class="alt" id="comment-0-text" >${ post.post_content }</div></div>`
}

function post_link(post) {
    let path = post2path(post)
    return `<a href='${path}' >${post.post_title}</a>`
}

function share_post(post) {
    let share_title = encodeURI(post.post_title).replace(/%20/g,' ')
    let share_link  = encodeURI('https://' + CONF.domain +  post2path(post) )
    return `<a href='mailto:?subject=${share_title}&body=${share_link}' title='email this' >share
            <img src='/images/mailicon.jpg' width=15 height=12 ></a>`
}

function midpage(...args) { // just an id so we can easily swap out the middle of the page
    return `<div id="midpage" >
        ${ args.join('') }
        </div>`
}

function new_post_button() {
    return '<a href="/new_post" class="btn btn-success btn-sm" title="start a new post" ><b>new post</b></a>'
}

function popup(message) {
    return `<script>alert('${ message }');</script>`
}

function lostpwform(login_failed_email) {
    var show = login_failed_email ? `value='${ login_failed_email }'` : `placeholder='email address'`

    return `
    <div id='lostpwform' >
        <h1>reset password</h1>
        <form action='/recoveryemail' method='post'>
            <div class='form-group'><input type='text' name='user_email' ${ show } class='form-control' id='lost_pw_email' ></div>
            <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
        </form>
        <script>document.getElementById('lost_pw_email').focus();</script>
    </div>`
}

function get_edit_link(c, current_user, ip) {

    if (!current_user) return ''

    if ((current_user.user_id === c.comment_author) || (current_user.user_level === 4)) {
        return `<a href='/edit_comment?c=${c.comment_id}&${create_nonce_parms(ip)}'>edit</a>`
    }

    return ''
}

function get_nuke_link(c, current_user, ip, req) {

    if (!current_user) return ''
    if (!req.url)      return ''

    return (URL.parse(req.url).pathname.match(/comment_moderation/) && (current_user.user_level === 4)) ?
        `<a href='/nuke?nuke_id=${c.comment_author}&${create_nonce_parms(ip)}' onClick='return confirm("Really?")' >nuke</a>` : ''
}

function id_box(current_user) {

    var img = render_user_icon(current_user, 0.4, `'align='left' hspace='5' vspace='2'`) // scale image down

    return `
        <div id='status' >
            ${img}<a href='/user/${current_user.user_name}' >${current_user.user_name}</a>
        </div>`
}

function loginprompt(login_failed_email) {

    return `
        <div id='status' >
            ${ login_failed_email ? 'login failed' : '' }
            <form id='loginform' >
                <fieldset>
                    <input id='email'    name='email'    placeholder='email'    type='text'     required >
                    <input id='password' name='password' placeholder='password' type='password' required >
                </fieldset>
                <fieldset>
                    <input type='submit' id='submit' value='log in'
                        onclick="$.post('/post_login', $('#loginform').serialize()).done(function(data) { $('#status').html(data) });return false">
                    <a href='#' onclick="midpage.innerHTML = lostpwform.innerHTML;  return false" >forgot password</a> /
                    <a href='#' onclick="midpage.innerHTML = registerform.innerHTML; return false" >register</a>
                </fieldset>
            </form>
            <div style='display: none;' >
                ${ lostpwform(login_failed_email)   }
                ${ registerform() }
            </div>
        </div>`
}

function icon_or_loginprompt(current_user, login_failed_email) {
    if (current_user) return id_box(current_user)
    else              return loginprompt(login_failed_email)
}

function comment_box(post, current_user, ip) { // add new comment, just updates page without reload

    let url = `/accept_comment?${create_nonce_parms(ip)}` // first href on button below is needed for mocha test
    return `<hr>Comment as
    ${current_user ? current_user.user_name : ip2anon(ip) }
    ${current_user ? '' : ' or <a href="#">log in</a> at top of page'}:
    ${render_upload_form()}
    <form id='commentform' >
        <textarea id='ta' name='comment_content' class='form-control' rows='10' ></textarea><p>
        <input type='hidden' name='comment_post_id' value='${post.post_id}' />
        <button class='btn btn-success btn-sm' id='accept_comment' href=${url} 
            onclick="$.post('${url}', $('#commentform').serialize()).done(function(response) {
                response = JSON.parse(response) // was a string, now is an object
                $('#comment_list').append(response.content)
                if (!response.err) document.getElementById('commentform').reset() // don't clear the textbox if error
            }).fail(function() {
                $('#comment_list').append('something went wrong on the server ')
            })
            return false" >submit</button>
    </form>`
}

function comment_pagination(comments, url) { // get pagination links for a single page of comments
    if (!comments || !url || (intval(comments.found_rows) <= 40)) return // no pagination links needed if one page or less

    let total    = comments.found_rows
    let pathname = URL.parse(url).pathname // "pathname" is url path without the ? parms, unlike "path"
    let query    = URL.parse(url).query

    if (!query || !query.match(/offset=\d+/)) { // offset missing means we are on the last page of comments, ie offset = total - 40
        var offset          = total - 40
        var previous_offset = (total - 80 > 0) ? total - 80 : 0 // second to last page
        var q               = query ? (query + '&') : ''

        var first_link = `${pathname}?${q}offset=0#comments`
        var prev_link  = `${pathname}?${q}offset=${previous_offset}#comments`
        var last_link  = `${pathname}${query ? ('?' + query) : ''}#last` // don't include the question mark unless q
        // there is no next_link because we are necessarily on the last page of comments
    }
    else { // there is a query string, and it includes offset; 0 means show first 40 comments
        var offset          = intval(_GET(url, 'offset'))
        var previous_offset = (offset - 40 > 0) ? offset - 40 : 0
        var next_offset     = (offset + 40 > total - 40) ? total - 40 : offset + 40 // last page will always be 40 comments

        if (offset !== 0) { // don't need these links if we are on the first page
            var first_link = `${pathname}?${query.replace(/offset=\d+/, 'offset=0')}#comments`
            var prev_link  = `${pathname}?${query.replace(/offset=\d+/, 'offset=' + previous_offset)}#comments`
        }

        if (offset < total - 40) var next_link = `${pathname}?${query.replace(/offset=\d+/, 'offset=' + next_offset)}#comments` // no next link on last page
        var last_link = `${pathname}?${query.replace(/offset=\d+/, 'offset=' + (total - 40))}#last`
    }

    let ret = `<p id='comments'>`
    if (typeof first_link !== 'undefined') ret = ret + `<a href='${first_link}' title='Jump to first comment' >&laquo; First</a> &nbsp; &nbsp;`
    if (typeof prev_link  !== 'undefined') ret = ret + `<a href='${prev_link}'  title='Previous page of comments' >&laquo; Previous</a> &nbsp; &nbsp; `

    let max_on_this_page = (total > offset + 40) ? offset + 40 : total
    ret = ret + `Comments ${offset + 1} - ${max_on_this_page} of ${total.number_format()} &nbsp; &nbsp; `

    if (typeof next_link  !== 'undefined') ret = ret + `<a href='${next_link}'  title='Next page of comments' >Next &raquo;</a> &nbsp; &nbsp; `

    return ret + `<a href='${last_link}' title='Jump to last comment' >Last &raquo;</a></br>`
}

function post_form(p, post) { // used both for composing new posts and for editing existing posts; distinction is the presence of p, the post_id

    const fn      = p ? 'edit' : 'new post'
    const title   = p ? post.post_title.replace(/'/g, '&apos;') : '' // replace to display correctly in single-quoted html value below
    const content = p ? newlineify(post.post_content.replace(/'/g, '&apos;')) : ''
    const post_id = p ? `<input type='hidden' name='post_id' value='${post.post_id}' />` : ''

    return `
    <h1>${fn}</h1>
    <form action='/accept_post' method='post' name='postform' >
        <div class='form-group'><input name='post_title' type='text' class='form-control' placeholder='title' id='title' value='${title}' ></div>
        <textarea class='form-control' name='post_content' rows='12' id='ta' name='ta' >${content}</textarea><p>
        ${post_id}
        <button type='submit' id='submit' class='btn btn-success btn-sm' >submit</button>
    </form>

    <script>
    document.getElementById('title').focus();
    </script>
    ${render_upload_form()}`
}

function comment_edit_box(comment, context) { // edit existing comment, redirect back to whole post page

    var current_user = context.current_user
    var ip           = context.ip

    comment.comment_content = newlineify(comment.comment_content)

    return `
    <h1>edit comment</h1>
    ${current_user ? render_upload_form() : ''}
    <form id='commentform' action='/accept_edited_comment?${create_nonce_parms(ip)}' method='post' >
        <textarea id='ta' name='comment_content' class='form-control' rows='10' placeholder='write a comment...' >${comment.comment_content}</textarea><p>
        <input type='hidden' name='comment_id' value='${comment.comment_id}' />
        <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
    </form>
    <script>document.getElementById('ta').focus();</script>`
}

function post_list(posts, context) { // format a list of posts from whatever source

    var current_user = context.current_user
    var url          = context.req.url

    if (!url) return ''
    if (!posts) return ''

    let nonce_parms = create_nonce_parms(context.ip)
    
    posts = posts.filter(post => {
        if (!current_user && post.post_title.match(/thunderdome/gi)) return false // hide thunderdome posts if not logged in
        if (!current_user && post.post_nsfw)                         return false // hide porn posts if not logged in

        if (current_user                                 &&
            current_user.relationships[post.post_author] &&
            current_user.relationships[post.post_author].rel_i_ban)  return false

        return true
    })

    let moderation = (URL.parse(url).pathname.match(/post_moderation/) && (current_user.user_level === 4)) ? 1 : 0

    return posts.map(post => post_summary(post, current_user, moderation, nonce_parms)).join('')
}

function post_summary(post, current_user, moderation, nonce_parms) { // format item in list of posts according to user and whether post is in moderation
    const unread        = render_unread_comments_icon(post, current_user) // last view by this user, from left join
    const imgdiv        = (current_user && current_user.user_hide_post_list_photos) ? '' : get_first_image(post)
    const arrowbox_html = arrowbox(post)
    const firstwords    = `<font size='-1'>${first_words(post.post_content, 30)}</font>`

    const approval_link = moderation ? ` <a href='#' onclick="$.get('/approve_post?post_id=${post.post_id}&${nonce_parms}',
        function() { $('#post-${ post.post_id }').remove() }); return false">approve</a>` : ''

    const delete_link = moderation ? ` <a href='/delete_post?post_id=${post.post_id}&${nonce_parms}'
        onClick="return confirm('Really delete?')" id='delete_post' >delete</a> &nbsp;` : ''

    const nuke_link = moderation ? ` <a href='/nuke?nuke_id=${post.post_author}&${nonce_parms}' onClick='return confirm("Really?")' >nuke</a>` : ''

    const latest = latest_comment(post)

    const link = `<b>${post_link(post)}</b>${extlink(post)}`

    const utz = current_user ? current_user.user_timezone : 'America/Los_Angeles'
    const date = render_date(post.post_date, utz, 'D MMM YYYY')

    return `<div class='post' id='post-${post.post_id}' >${arrowbox_html}${imgdiv}${link}
    <br>by <a href='/user/${ post.user_name }'>${ post.user_name }</a> on ${date}&nbsp;
    ${latest} ${unread} ${approval_link} ${delete_link} ${nuke_link}<br>${firstwords}</div>`
}

function extlink(post) { // format first external link from post
    let extlinks = get_external_links(post.post_content)
    if (extlinks && extlinks.length && URL.parse(extlinks[0]).host) {
        var host = URL.parse(extlinks[0]).host.replace(/www./, '').substring(0, 31)
        return ` (<a href='${brandit(extlinks[0])}' target='_blank' title='original story' >${host})</a>`
    }
    else return ''
}

function latest_comment(post) {

    let ago  = MOMENT(post.post_modified).fromNow()
    let num  = post.post_comments.number_format()
    let path = post2path(post)
    let s    = post.post_comments === 1 ? '' : 's'

    return post.post_comments ?
        `<a href='${path}'>${num}&nbsp;comment${s}</a>, latest <a href='${path}#comment-${post.post_latest_comment_id}' >${ago}</a>` :
        `<a href='${post2path(post)}'>Posted ${ago}</a>`
}

function get_first_image(post) {

    let c = CHEERIO.load(post.post_content)

    if (!c('img').length) return ''

    let src = post.post_nsfw ? '/images/nsfw.png' : c('img').attr('src')

    return `<div class='icon' ><a href='${post2path(post)}' ><img src='${src}' border=0 width=100 align=top hspace=5 vspace=5 ></a></div>`
}

function comment_list(comments, context) { // format one page of comments

    let offset = _GET(context.req.url, 'offset')

    return `<div id='comment_list' >
    ${ comments.length ? comments.map(item => format_comment(item, context, comments, offset)).join('') : '<b>no comments found</b>' }
    </div>`
}
