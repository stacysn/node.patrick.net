//base_url  = 'https://patrick.net'
base_url  = 'http://dev.patrick.net'
test_user = {
    email     : 'badraig@yahoo.com',
    password  : process.env.test_password,
    user_name : 'badraig',
}

JSDOM     = require('jsdom').JSDOM
assert    = require('assert')
request   = require('request')
j         = request.jar()
request   = request.defaults({jar:j})
cookie    = null
rand      = null
post_id   = null
matches   = null
post_html = null

it('about page should return 200 and contain "about"', function (done) {
    request.get(base_url + '/about', function (err, res, body) {
        assert.equal(res.statusCode, 200)
        assert.ok(body.match(/about/), 'about page proof')
        done()
    })
})

it('home page should return 200 and contain "patrick.net"', function (done) {
    request.get(base_url + '/', function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        assert.ok(body.match(/patrick.net/), 'site proof')
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

    rand = `test post ${Math.random()}`

    var options = {
        method  : 'POST',
        url     : base_url + '/accept_post',
        form    : {
            post_title   : rand,
            post_content : rand,
        },
    }

    request.post(options, function (err, resp, body) {
        assert.ok(matches = resp.headers['location'].match(/\/post\/(\d+)/), 'new post proof')
        post_id = matches[1]
        assert.ok(!err, 'no error')
        done()
    })
})
it('post page should show the right title', function (done) {
    request.get(`${base_url}/post/${post_id}`, function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        assert.ok(body.match(rand), 'post proof')
        post_html = body // needed for delete test below
        done()
    })
})

it('home page should show the new test post', function (done) {
    request.get(base_url + '/', function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        assert.ok(body.match(rand), 'post proof')
        done()
    })
})

it('should delete test post', function (done) {

    const dom = new JSDOM(post_html) // post_html from previous test

    let href = base_url + dom.window.document.getElementById('delete_post').href

    request.get(href, function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        assert.ok(body.match(/post deleted/), 'post deleted')
        done()
    })
})


