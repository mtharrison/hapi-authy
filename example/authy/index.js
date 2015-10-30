var Authy = require('authy');
var Boom = require('boom');


var internals = {};


internals.scheme = function (server, options) {

    var authy = Authy(options.apiKey, options.sandbox ? 'http://sandbox-api.authy.com' : null);

    var cookieOptions = {
        encoding: 'iron',
        path: '/',
        password: 'dkfhdsj',
        isSecure: false
    };

    server.state('authy', cookieOptions);

    return {
        authenticate: function (request, reply) {

            if (!cookie) {
                return reply(Boom.unauthorized('Missing authy cookie'));
            }

            console.log(cookie);

            if (request.method === 'get') {
                if (!cookie.authyId) {
                    return reply.view('twofa/register', { path: request.path });
                }

                if (!cookie.verified) {
                    return reply.view('twofa/verify', { path: request.path });
                }
            }

            reply.continue({ credentials: cookie });
        },
        payload: function (request, reply) {

            var cookie = request.state.authy;
            var payload = request.payload;

            if (payload.phone && payload.country) {
                return authy.register_user(cookie.email, payload.phone, payload.country, true, function (err, res) {

                    if (err || !res.success) {
                        return reply(Boom.unauthorized('Could\'t register user'));
                    }

                    cookie.authyId = res.user.id;
                    reply.redirect(request.path).state('authy', cookie);
                });
            }

            if (request.payload.token) {
                return authy.verify(cookie.authyId, payload.token, function (err, res) {

                    if (err) {
                        return reply(Boom.unauthorized('Could\'t validate token'));
                    }

                    cookie.verified = true;
                    reply.redirect(request.path).state('authy', cookie);
                });
            }

            reply(Boom.unauthorized('Invalid payload'));
        }
    }
};

exports.register = function (server, options, next) {

    server.auth.scheme('authy', internals.scheme);
    next();
};

exports.register.attributes = { name: 'authy', version: '1.0.0' };
