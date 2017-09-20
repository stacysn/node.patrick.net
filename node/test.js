assert  = require('assert')
request = require('request')

var j = request.jar()
var request = request.defaults({jar:j})
var cookie

it('about page should return 200 and contain "about"', function (done) {
    request.get('http://dev.patrick.net/about', function (err, res, body) {
        assert.equal(res.statusCode, 200)
        assert.ok(body.match(/about/), 'about page proof')
        done()
    })
})

it('home page should return 200 and contain "patrick.net"', function (done) {
    request.get('http://dev.patrick.net/', function (err, res, body) {
        assert.equal(res.statusCode, 200, 'status code 200')
        assert.ok(body.match(/patrick.net/), 'site proof')
        done()
    })
})

it('should get cookie', function (done) {

    var options = {
        method  : 'POST',
        url     : 'http://dev.patrick.net/post_login',
        form    : {
            'email'    : 'p@patrick.net',
            'password' : '45e760'
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

    request('http://dev.patrick.net/user/Patrick', function (err, resp, body) {
        assert.ok(!err, 'no error')
        assert.ok(body.match(/logout/), 'login proof')
        assert.ok(!body.match(/login/), 'more login proof')
        done()
    })
})
