// mocha upness monitor to be run from cron

base_url  = 'https://patrick.net'
//base_url  = 'http://dev.patrick.net'

assert  = require('assert')
request = require('request')

console.log(new Date())

it('home page should return 200 and contain "new post" button', function (done) {
    request.get(base_url + '/', function (err, res, body) {
        assert.equal(res.statusCode, 200)
        assert.ok(body.match(/new post/), 'home page proof')
        assert.ok(body.length > 20000, 'home page big enough')
        assert.ok(body.length < 90000, 'home page small enough')
        done()
    })
})
