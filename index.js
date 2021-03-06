'use strict';

const Boom = require('boom');
const Hoek = require('hoek');
const Joi = require('joi');
const Package = require('./package');

const internals = {
    defaults: {
        register: (request, reply) => {

            reply.view('authy/register', { path: request.path });
        },
        verify: (request, reply) => {

            reply.view('authy/verify', {
                path: request.path,
                requestTokenUrl: request.plugins.authy.requestTokenUrl
            });
        },
        failRegister: (err, request, reply) => {

            reply(Boom.unauthorized('Could\'t register user'));
        },
        failVerify: (err, request, reply) => {

            reply(Boom.unauthorized('Could\'t validate token'));
        },
        tokenRequested: (err, request, reply) => {

            reply.redirect(request.query.returnUrl);
        }
    }
};


internals.schemeOptionsSchema = {
    apiKey: Joi.string().required(),
    cookieName: Joi.string().default('authy'),
    requestTokenUrl: Joi.string().default('/authy-request-token'),
    sandbox: Joi.boolean().default(false),
    cookieOptions: Joi.object().keys({
        encoding: Joi.string().valid('iron')
    }).options({ allowUnknown: true }),
    sandboxUrl: Joi.string().default('http://sandbox-api.authy.com'),
    funcs: Joi.object().keys({
        register: Joi.func().default(internals.defaults.register),
        verify: Joi.func().default(internals.defaults.verify),
        failRegister: Joi.func().default(internals.defaults.failRegister),
        failVerify: Joi.func().default(internals.defaults.failVerify),
        tokenRequested: Joi.func().default(internals.defaults.tokenRequested)
    }).default({
        register: internals.defaults.register,
        verify: internals.defaults.verify,
        failRegister: internals.defaults.failRegister,
        failVerify: internals.defaults.failVerify,
        tokenRequested: internals.defaults.tokenRequested
    }),
    client: Joi.func().default(require('authy')),
    requestTokenRouteConfig: Joi.object().default({})
};


internals.scheme = function (server, options) {

    const result = Joi.validate(options, internals.schemeOptionsSchema);
    Hoek.assert(!result.error, result.error);
    const settings = result.value;
    const authy = settings.client(settings.apiKey, settings.sandbox ? settings.sandboxUrl : null);

    server.state(settings.cookieName, settings.cookieOptions);

    server.route({
        config: settings.requestTokenRouteConfig,
        method: 'GET',
        path: settings.requestTokenUrl,
        handler: function (request, reply) {

            authy.request_sms(request.state[settings.cookieName].authyId, (err, res) => {

                settings.funcs.tokenRequested(err, request, reply);
            });
        }
    });

    return {
        authenticate: function (request, reply) {

            request.plugins.authy = request.plugins.authy || {};
            request.plugins.authy.requestTokenUrl = settings.requestTokenUrl;

            const cookie = request.state[settings.cookieName];

            if (!cookie) {
                return reply(Boom.unauthorized('Missing authy cookie'));
            }

            // Route to appropriate stage

            if (request.method === 'get') {
                if (!cookie.authyId) {
                    return settings.funcs.register(request, reply);
                }

                if (!cookie.verified) {
                    return settings.funcs.verify(request, reply);
                }
            }

            // Success

            reply.continue({ credentials: cookie });
        },
        payload: function (request, reply) {

            const cookie = request.state[settings.cookieName];
            const payload = request.payload;

            // Registration payload

            if (!cookie.authyId) {
                const schema = {
                    country: Joi.number().required(),
                    phone: Joi.number().required()
                };

                const payloadResult = Joi.validate(request.payload, schema);

                if (payloadResult.error) {

                    return settings.funcs.failRegister(payloadResult.error, request, reply);
                }

                return authy.register_user(cookie.email, payload.phone, payload.country, true, (err, res) => {

                    if (err) {
                        return settings.funcs.failRegister(err, request, reply);
                    }

                    cookie.authyId = res.user.id;
                    reply.redirect(request.path).state(settings.cookieName, cookie);
                });
            }

            // Verification payload

            const schema = { token: Joi.number().required() };
            const payloadResult = Joi.validate(request.payload, schema);

            if (payloadResult.error) {
                return settings.funcs.failVerify(payloadResult.error, request, reply);
            }

            return authy.verify(cookie.authyId, payload.token, (err, res) => {

                if (err) {
                    return settings.funcs.failVerify(err, request, reply);
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
