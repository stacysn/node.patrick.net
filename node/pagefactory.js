// The page factory never does IO. It simply assembles pages from state.

state = {}
pages = {}

exports.render = function(s, page) {
    state = s
    return pages[page]();
}

pages.home = function () {

    return html(
        header(),
        body(
            post(),
            comment_list()
            ),
        footer()
    )
}

function html(...args) {
    return `<html>${ args.join('') }</html>`
}

function header() {
    return `header has date ${ new Date().toUTCString() }`
}

function body(...args) {
    return `<body><p>${ state.body + args.join('') }</body>`
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
