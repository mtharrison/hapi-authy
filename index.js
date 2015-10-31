'use strict';

const Authy = require('authy');
const Boom = require('boom');
const Hoek = require('hoek');
const Joi = require('joi');
const Package = require('./package');
const Uuid = require('uuid');


const internals = {
    schemeOptionsSchema: {
        apiKey: Joi.string().required(),
        cookieName: Joi.string().default('authy'),
        generateSmsPath: Joi.string().default('/authy-generate-sms'),
        sandbox: Joi.boolean().default(false),
        cookieOptions: Joi.object(),
        sandboxUrl: Joi.string().default('http://sandbox-api.authy.com'),
        funcs: {
            registerFunc: Joi.func().required(),
            verifyFunc: Joi.func().required(),
            registerError: Joi.func().default(function (err, request, reply) {

                return reply(Boom.unauthorized('Could\'t register user'));    
            }),
            verifyError: Joi.func().default(function (err, request, reply) {

                return reply(Boom.unauthorized('Could\'t validate token'));
            })
        }
    }
};


internals.scheme = function (server, options) {

    const uuid = Uuid.v4();
    const result = Joi.validate(options, internals.schemeOptionsSchema);
    Hoek.assert(!result.error, result.error);
    const settings = result.value;
    const authy = Authy(settings.apiKey, settings.sandbox ? settings.sandboxUrl : null);

    server.state(settings.cookieName, settings.cookieOptions);

    server.route({
        method: 'GET',
        path: settings.generateSmsPath,
        handler: function (request, reply) {

            authy.request_sms(request.state[settings.cookieName].authyId, (err, res) => {

                reply('ok');
            });
        }
    });

    return {
        authenticate: function (request, reply) {

            const cookie = request.state[settings.cookieName];
            request.plugins.authy = request.plugins.authy || {};
            request.plugins.authy.generateSmsPath = settings.generateSmsPath;

            if (!cookie) {
                return reply(Boom.unauthorized('Missing authy cookie'));
            }

            if (request.method === 'get') {
                if (!cookie.authyId) {
                    return settings.funcs.registerFunc(request, reply);
                }

                if (!cookie.verified) {
                    return settings.funcs.verifyFunc(request, reply);
                }
            }

            reply.continue({ credentials: cookie });
        },
        payload: function (request, reply) {

            const cookie = request.state[settings.cookieName];
            const payload = request.payload;

            if (!cookie.authyId) {
                let schema = {
                    country: Joi.number().required(),
                    phone: Joi.number().required()
                };

                let result = Joi.validate(request.payload, schema);

                if (result.error) {
                    return settings.funcs.registerError(result.error, request, reply);
                }

                return authy.register_user(cookie.email, payload.phone, payload.country, true, (err, res) => {

                    if (err) {
                        return settings.funcs.registerError(err, request, reply);
                    }

                    cookie.authyId = res.user.id;
                    reply.redirect(request.path).state(settings.cookieName, cookie);
                });
            }

            let schema = { token: Joi.number().required() };
            let result = Joi.validate(request.payload, schema);

            if (result.error) {
                return settings.funcs.verifyError(result.error, request, reply);
            }

            return authy.verify(cookie.authyId, payload.token, (err, res) => {

                if (err) {
                    return settings.funcs.verifyError(err, request, reply);
                }

                cookie.verified = true;
                reply.redirect(request.path).state(settings.cookieName, cookie);
            });
        }
    };
};


exports.register = function (server, options, next) {

    server.auth.scheme('authy', internals.scheme);
    next();
};


exports.register.attributes = { name: Package.name, version: Package.version };
