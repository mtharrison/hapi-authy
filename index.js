var Authy = require('authy');
var Boom = require('boom');
var Hoek = require('hoek');
var Joi = require('joi');
var Package = require('./package');


var internals = {
    schemeOptionsSchema: {
        apiKey: Joi.string().required(),
        cookieName: Joi.string().default('authy'),
        sandbox: Joi.boolean().default(false),
        cookieOptions: Joi.object(),
        sandboxUrl: Joi.string().default('http://sandbox-api.authy.com'),
        registerFunc: Joi.func().required(),
        verifyFunc: Joi.func().required()
    }
};


internals.scheme = function (server, options) {

    var result = Joi.validate(options, internals.schemeOptionsSchema);
    Hoek.assert(!result.error, result.error);

    var settings = result.value;
    var authy = Authy(settings.apiKey, settings.sandbox ? settings.sandboxUrl : null);

    server.state(settings.cookieName, settings.cookieOptions);

    return {
        authenticate: function (request, reply) {

            var cookie = request.state[settings.cookieName];

            if (!cookie) {
                return reply(Boom.unauthorized('Missing authy cookie'));
            }

            if (request.method === 'get') {
                if (!cookie.authyId) {
                    return settings.registerFunc(request, reply);
                }

                if (!cookie.verified) {
                    return settings.verifyFunc(request, reply);
                }
            }

            reply.continue({ credentials: cookie });
        },
        payload: function (request, reply) {

            var cookie = request.state[settings.cookieName];
            var payload = request.payload;

            if (payload.phone && payload.country) {
                return authy.register_user(cookie.email, payload.phone, payload.country, true, function (err, res) {

                    if (err || !res.success) {
                        return reply(Boom.unauthorized('Could\'t register user'));
                    }

                    cookie.authyId = res.user.id;
                    reply.redirect(request.path).state(settings.cookieName, cookie);
                });
            }

            if (request.payload.token) {
                return authy.verify(cookie.authyId, payload.token, function (err, res) {

                    if (err) {
                        return reply(Boom.unauthorized('Could\'t validate token'));
                    }

                    cookie.verified = true;
                    reply.redirect(request.path).state(settings.cookieName, cookie);
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


exports.register.attributes = { name: Package.name, version: Package.version };
