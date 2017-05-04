// The page factory never does IO. It simply assembles a page from state, which will be overwritten on each call to render()
// state does not change at all once render is called

var state = {}

exports.render = s => {
    state = s
    return pages[state.page]()
}

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

Array.prototype.sortByProp = function(p){
    return this.sort(function(a,b){
        return (a[p] > b[p]) ? 1 : (a[p] < b[p]) ? -1 : 0
    })
}
