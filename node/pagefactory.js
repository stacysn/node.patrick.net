// The page factory never does IO. It simply assembles a page from state, which will be overwritten on each call to render()

var state = {}
var pages = {}

exports.render = function(s, page) {
    state = s
    return pages[page]();
}

pages.home = function () {

    return html(
        head(),
        body(
            header(),
            h1(),
            post(),
            comment_list(),
            footer()
        )
    )
}

function html(...args) {
    return `<!DOCTYPE html><html lang="en">${ args.join('') }</html>`
}

function head() {
    return `<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" >
<link href="/css/bootstrap.20160501.css" rel="stylesheet" >
</head>`
}

function header() {
    return `header has date ${ new Date().toUTCString() }`
}

function h1() {
    return `<h1>${ state.message }</h1>`
}

function body(...args) {
    return `<body>${ state.body + args.join('') }</body>`
}

function post() {
    return '<p>post'
}

function comment_list() {
    return `<p id='${ arguments.callee.name + comment_list.i++ }' >comment_list `
}
comment_list.i = 0

function footer() {
    return '<p>foother'
}
