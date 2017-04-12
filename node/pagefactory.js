// The page factory never does IO. It simply assembles a page from state, which will be overwritten on each call to render()

var state = {}
var pages = {}

exports.render = function(s) {
    state = s
    return pages[state.page]();
}

pages.home = function () {
    return html(
        head(),
        body(
            header(),
            tabs(),
            tagline(),
            address_list(),
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
            footer()
        )
    )
}

pages.login = function () {
    return icon_or_loginprompt()
}

pages.logout = function () {
    return loginprompt()
}

function html(...args) {
    return `<!DOCTYPE html>
        <html lang="en">
        ${ args.join('') }
        <script async src="/js/jquery.min.js"></script>
        </html>`
}

function head() {
    return `<head>
        <link href="/css/style_20170309.css" rel="stylesheet" type="text/css" />
        <link rel="icon" href="/favicon.ico" />
        <meta charset="utf-8" />
        <meta name="description" content="real estate, offers, bids" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <title>What Did You Bid?</title>
        </head>`
}

function header() {
    return `<div class="headerbox" >
        <a href="/" ><font color="ba114c"><h3 title="back to home page" >What Did You Bid?</h3></font></a> &nbsp;
        <div style="float:right">${ icon_or_loginprompt() }</div><p>
        <a href="/addressform" class="btn btn-success btn-sm" title="start writing about a new address" ><b>add new address</b></a>
        </div>`
}

function icon_or_loginprompt() {
    if (state.user) return icon()
    else            return loginprompt()
}

function icon() {
    return `<div id='status' >
        <a href='/users/${state.user.user_screenname}' ><img src='${state.user.user_icon}'
            width='${state.user.user_icon_width}' height='${state.user.user_icon_height}' > ${state.user.user_screenname}</a>
        <p>
        <a HREF='#' onclick="$.get('/logout', function(data) { $('#status').html(data) });return false">logout</a>
        </div>`
}

function loginprompt() {
    return `<div id='status' >
        ${ state.login_failed ? 'login failed' : '' }
        <form id='loginform' action='/login' >
            <fieldset id="inputs">
                <input id="email"    type="text"     placeholder="email"    name="email"    required >   
                <input id="password" type="password" placeholder="password" name="password" required >
            </fieldset>
            <fieldset id="actions">
                <input type="submit" id="submit" value="log in"
                    onclick="$.post('/login', $('#loginform').serialize()).done(function(data) { $('#status').html(data) });return false">
                </script>

                <a href="">forgot your password?</a> <a href="">register</a>
            </fieldset>
        </form>
        </div>`
}

function tabs() {
    return `<ul class="nav nav-tabs">
        <li class="active" > <a href="/?order=active"   title="most recent comments" >active</a></li>
        <li                > <a href="/?order=comments" title="most comments"        >comments</a></li>
        <li                > <a href="/?order=new"      title="newest"               >new</a></li>
        <li                > <a href="/?order=private"  title="your private chats"   >private</a></li>
        </ul>`
}

function addressform() {
    return `
    <h1>add new address</h1>
    <form action='/postaddress' method='post' >
        <div class='form-group'><input name='address_num_street' type='text' class='form-control' placeholder='number and street only, like 123 Shady Lane' 
                id='address_num_street' ></div>
        <div class='form-group'> <input name='address_apt' type='text' class='form-control' placeholder='apartment number, if any' > </div>
        <div class='form-group'> <input name='address_zip' type='text' class='form-control' placeholder='5 digit zip code' > </div>
        <button type='submit' id='submit' class='btn btn-success btn-sm'>submit</button>
    </form>
    <script type="text/javascript">document.getElementById('address_num_street').focus();</script>`
}

function tagline() {
    return `<h1>Increase fair play for buyers and sellers</h1>`
}

function body(...args) {
    return `<body>
        <div class="container" >
        ${ args.join('') }
        </div>
        </body>`
}

function address_list() {
    tmp = ''

    for (i=0; i<3; i++) tmp = tmp + address()

    return tmp
}

function address() {
    return `<div class="address" ><a href="/address/number/slug">address</a></div>`
}

function comment_list() {
    return `<p id='${ arguments.callee.name + comment_list.i++ }' >comment_list `
}
comment_list.i = 0

function footer() {
    return `
        <p>
        <center>
        <a href='/'>home</a> &nbsp;
        <a href='#'>top</a> &nbsp;
        <a href="/users">users</a> &nbsp;
        <a href="/about">about</a> &nbsp;
        <a href='/1302130/2017-01-28-patnet-improvement-suggestions'>suggestions</a> &nbsp;
        <a href='mailto:p@patrick.net?subject=%2F' >contact</a> &nbsp;
        search box goes here
        `
}
