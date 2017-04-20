// The page factory never does IO. It simply assembles a page from state, which will be overwritten on each call to render()

var state = {}
var pages = {}

exports.render = function(s) {
    state = s
    return pages[state.page]()
}

pages.home = function () {
    return html(
        head(),
        body(
            header(),
            h1(),
            address_list(),
            new_address_button(),
            footer()
        )
    )
}

pages.users = function () {
    return pages.message()
}

pages.about = function () {
    return pages.message()
}

pages.message = function () {
    return html(
        head(),
        body(
            header(),
            h1(),
            text(),
            footer()
        )
    )
}

pages.registerform = function () {
    return html(
        head(),
        body(
            header(),
            registerform(),
            footer()
        )
    )
}

pages.lostpwform = function () {
    return html(
        head(),
        body(
            header(),
            lostpwform(),
            footer()
        )
    )
}

pages.addressform = function () {
    return html(
        head(),
        body(
            header(),
            addressform(),
            footer()
        )
    )
}

pages.address = function () {
    return html(
        head(),
        body(
            header(),
            address(),
            comment_list(),
            commentbox(),
            footer()
        )
    )
}

pages.key_login = function () {
    return pages.home()
}

pages.post_login = function () {
    return icon_or_loginprompt()
}

pages.logout = function () {
    return loginprompt()
}

pages.postcomment = function () {
    return comment()
}

pages.alert = function () {
    return alert()
}

//////////////////////////////////////// end of pages; all html is below ////////////////////////////////////////

function html(...args) {
    return `<!DOCTYPE html><html lang="en">
        ${ args.join('') }
        <script async src="/js/jquery.min.js"></script>
        </html>`
}

function head() {
    return `<head>
        <link href='/css/style_20170309.css' rel='stylesheet' type='text/css' />
        <link rel='icon' href='/favicon.ico' />
        <meta charset='utf-8' />
        <meta name='description' content='real estate, offers, bids' />
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no' />
        <title>What Did You Bid?</title>
        </head>`
}

function header() {
    return `<div class='headerbox' >
        <a href='/' ><font color='ba114c'><h3 title='back to home page' >What Did You Bid?</h3></font></a> &nbsp;
        <div style='float:right'>${ icon_or_loginprompt() }</div><p>
        </div>`
}

function icon_or_loginprompt() {
    if (state.user) return icon()
    else            return loginprompt()
}

function icon() {

    var img = state.user.user_icon ?
        `<img src='${state.user.user_icon}' width='${state.user.user_icon_width}' height='${state.user.user_icon_height}' >` : ''

    return `<div id='status' >
        <a href='/users/${state.user.user_screenname}' >${img} ${state.user.user_screenname}</a>
        <p>
        <a HREF='#' onclick="$.get('/logout', function(data) { $('#status').html(data) });return false">logout</a>
        </div>`
}

function loginprompt() {
    return `<div id='status' >
        ${ state.login_failed ? 'login failed' : '' }
        <form id='loginform' >
            <fieldset id='inputs'>
                <input id='email'    type='text'     placeholder='email'    name='email'    required >   
                <input id='password' type='password' placeholder='password' name='password' required >
            </fieldset>
            <fieldset id='actions'>
                <input type='submit' id='submit' value='log in'
                    onclick="$.post('/post_login', $('#loginform').serialize()).done(function(data) { $('#status').html(data) });return false">

                <a href='/lostpwform'>forgot your password?</a> <a href='/registerform'>register</a>
            </fieldset>
        </form>
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
        <h1>register</h1>
        <form action='/registration' method='post'>
        <div >
            <div class='form-group'><input type='text' name='user_screenname' placeholder='choose username' class='form-control' id='user_screenname' ></div>
            <div class='form-group'><input type='text' name='user_email'      placeholder='email address'   class='form-control'                      ></div>
        </div>
        <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
        </form>
        <script type="text/javascript">document.getElementById('user_screenname').focus();</script>`
}

function lostpwform() {
    var show = state.email ? `value='${ state.email }'` : `placeholder='email address'`

    return `
        <h1>reset password</h1>
        <form action='/recoveryemail' method='post'>
        <div class='form-group'><input type='text' name='user_email' ${ show } class='form-control' ></div>
        <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
        </form>
        <script type="text/javascript">document.getElementById('user_email').focus();</script>`
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
        <input type='hidden' name='comment_author'     value='${ state.user ? state.user.user_id : 0 }' ><p>
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

function comment() {
    return `<div class="comment" >${ state.comment.comment_created } ${ state.comment.comment_content }</div>`
}

function body(...args) {
    return `<body>
        <div class="container" >
        ${ args.join('') }
        </div>
        </body>`
}

function address_list() {

    if (state.addresses) {
        var formatted = state.addresses.map( (item) => {
            return `<div class="address" ><a href="/address/${item.address_id}/slug">
            ${item.address_num_street},
            ${item.zip_city}
            ${item.zip_state}
            ${item.zip_code}
            </a></div>`
        })
    }
    else formatted = []

    return formatted.join('')
}

function new_address_button() {
    return '<a href="/addressform" class="btn btn-success btn-sm" title="start writing about a new address" ><b>add new address</b></a>'
}

function address() {
    return `<h1><a href="/address/${state.address.address_id}/slug">
    ${state.address.address_num_street},
    ${state.address.zip_city}
    ${state.address.zip_state}
    ${state.address.zip_code}
    </a></h1>`
}

function comment_list() {
    if (state.comments) {
        var formatted = state.comments.map( (item) => {
            state.comment = item // so that comment() will pick up the right data
            return comment()
        })
        state.comment = null

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
        `
}

function alert() {
    return `<script type='text/javascript'> alert('${ state.alert_content }'); </script>`
}
