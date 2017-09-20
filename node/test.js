//base_url  = 'https://patrick.net'
base_url  = 'http://dev.patrick.net'
test_user = {
    email     : 'badraig@yahoo.com',
    password  : process.env.test_password,
    user_name : 'badraig',
}

assert  = require('assert')
request = require('request')
j       = request.jar()
request = request.defaults({jar:j})
cookie  = null

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

    var options = {
        method  : 'POST',
        url     : base_url + '/accept_post',
        form    : {
            post_title   : 'test post ' + Math.random(),
            post_content : Math.random() 
        },
    }

    request.post(options, function (err, resp, body) {
        assert.ok(!err, 'no error')
        done()
    })
})

