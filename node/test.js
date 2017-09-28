//base_url  = 'http://dev.patrick.net'
//base_url  = 'http://node.patrick.net'
//base_url  = 'https://patrick.net'

test_user = {
    email     : 'badraig@yahoo.com',
    password  : process.env.test_password,
    user_name : 'badraig',
}

JSDOM          = require('jsdom').JSDOM
assert         = require('assert')
request        = require('request')
j              = request.jar()
request        = request.defaults({jar:j})
cookie         = null
delete_link    = null
dom            = null
matches        = null
post_html      = null
post_id        = null
random_post    = `test post:    ${Math.random()}` // has to be unique because of constraint on post titles
random_comment = `test comment: ${Math.random()}`

it('about page should return 200 and contain "about"', function (done) {
    request.get(base_url + '/about', function (err, res, body) {
        assert.equal(res.statusCode, 200)
        assert.ok(body.match(/about/), 'about page proof')
        done()
    })
})

it('non-existent post should return 200 and contain "No post with id"', function (done) {
    request.get(base_url + '/post/0', function (err, res, body) {
        assert.equal(res.statusCode, 200)
        assert.ok(body.match(/No post with id/), 'invalid post id')
        done()
    })
})

it('should get cookie', function (done) {

    var options = {
        method  : 'POST',
        url     : base_url + '/post_login',
        form    : {
            email    : test_user.email,
            password : test_user.password,
        },
    }

    request.post(options, function (err, resp, body) {
        cookie = resp.headers['set-cookie'][0]
        assert.ok(cookie.match(/patricknetuser/), 'cookie proof')
        assert.ok(!err, 'no error')
        done()
    })
})

it('should get logged in page', function (done) {

    request(base_url + '/user/' + test_user.user_name, function (err, resp, body) {
        assert.ok(!err, 'no error')
        assert.ok(body.match(/logout/), 'login proof')
        assert.ok(!body.match(/login/), 'more login proof')
        done()
    })
})

it('should create a post', function (done) {

    var options = {
        method  : 'POST',
        url     : base_url + '/accept_post',
        form    : {
            post_title   : random_post,
            post_content : random_post,
        },
    }

    request.post(options, function (err, resp, body) {
        assert.ok(matches = resp.headers['location'].match(/\/post\/(\d+)/), 'new post proof')
        post_id = matches[1]
        assert.ok(!err, 'no error')
        done()
    })
})

it('post page should show the right content', function (done) {
    request.get(`${base_url}/post/${post_id}`, function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        assert.ok(body.match(random_post), 'post proof')
        post_html = body
        dom = new JSDOM(post_html) // needed for comment and delete tests below
        done()
    })
})

it('home page should show the new test post', function (done) {
    request.get(base_url + '/', function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        assert.ok(body.match(/patrick.net/), 'site proof')
        assert.ok(body.match(random_post), 'post on home page proof')
        done()
    })
})

it('should create a comment', function (done) {

    var item = dom.window.document.getElementById('accept_comment')

    for(var j = 0; j < item.attributes.length; j++) {
        if ('href' === item.attributes[j].name) var href = base_url + item.attributes[j].value
    }

    var options = {
        method  : 'POST',
        url     : href,
        form    : {
            comment_content : random_comment,
            comment_post_id : post_id,
        },
    }

    request.post(options, function (err, resp, body) {
        assert.ok(body.match(random_comment), 'new comment proof')
        assert.ok(!err, 'no error')
        var a = require('cheerio').load(body)("a:contains(delete)")[0].attribs.onclick
        matches = a.match(/'(.delete_comment.*?)'/) // grab the delete link for a test below
        delete_link = matches[1]
        done()
    })
})

it('post should show the new comment', function (done) {
    request.get(base_url + `/post/${post_id}`, function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        assert.ok(body.match(random_comment), 'comment proof')
        done()
    })
})

it('should delete the comment', function (done) {
    request.get(base_url + delete_link, function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        done()
    })
})

it('post should no longer show the new comment', function (done) {
    request.get(base_url + `/post/${post_id}`, function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        assert.ok(!body.match(random_comment), 'comment proof')
        done()
    })
})

it('should delete test post', function (done) {

    let href = base_url + dom.window.document.getElementById('delete_post').href

    request.get(href, function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        assert.ok(body.match(/post deleted/), 'post deleted')
        done()
    })
})
