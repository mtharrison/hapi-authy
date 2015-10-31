'use strict';

const Bcrypt = require('bcryptjs');
const Hapi = require('hapi');
const Joi = require('joi');
const Path = require('path');

const server = new Hapi.Server();
server.connection({ port: 4000 });

const users = {
    'hi@matt-harrison.com': {
        password: '$2a$08$.sI.S6l9lL0crviIOn/EUuAc/0oTlBA9R0b6rGEJYRD2p2h76bKK.',
        requireTfa: false,
        authyId: null
    }
};

server.register([
    { register: require('vision') },
    { register: require('hapi-auth-cookie') },
    { register: require('..') }
], (err) => {

    if (err) {
        throw err;
    }

    server.auth.strategy('session', 'cookie', {
        password: 'Q3QJIcIIvKcMwG7c',
        cookie: 'sid-example',
        redirectTo: '/login',
        isSecure: false
    });

    server.auth.strategy('authy', 'authy', {
        apiKey: 'ikdsVwp8503GNcAqMLC2GToxj1EXq3Yq',
        sandbox: false,
        cookieOptions: {
            isSecure: false,
            path: '/',
            encoding: 'iron',
            password: 'Q3QJIcIIvKcMwG7c'
        },
        funcs: {
            register: function (request, reply) {

                reply.view('register', { path: request.path });
            },
            verify: function (request, reply) {

                reply.view('verify', {
                    path: request.path,
                    smsPath: request.plugins.authy.smsPath
                });
            }
        }
    });

    server.views({
        engines: {
            hbs: require('handlebars')
        },
        path: Path.join(__dirname, 'templates'),
        layout: true,
        isCached: false
    });

    server.route({
        method: 'GET',
        path: '/',
        config: {
            auth: 'session'
        },
        handler: function (request, reply) {

            reply.view('index');
        }
    });

    server.route({
        method: 'GET',
        path: '/login',
        handler: function (request, reply) {

            reply.view('login');
        }
    });

    server.route({
        method: 'GET',
        path: '/logout',
        config: {
            auth: 'session'
        },
        handler: function (request, reply) {

            request.auth.session.clear();
            reply.redirect('/');
        }
    });

    server.route({
        method: ['GET', 'POST'],
        path: '/authy',
        config: {
            auth: {
                strategies: ['authy'],
                payload: true
            },
            handler: function (request, reply) {

                const credentials = request.auth.credentials;
                const user = users[credentials.email];
                user.requireTfa = true;
                user.authyId = credentials.authyId;
                request.auth.session.set(user);
                return reply.redirect('/');
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/login',
        config: {
            validate: {
                payload: {
                    email: Joi.string().email().required(),
                    password: Joi.string().required(),
                    tfa: Joi.boolean().default(false)
                }
            }
        },
        handler: function (request, reply) {

            const email = request.payload.email;
            const password = request.payload.password;
            const tfa = request.payload.tfa;

            const user = users[email];

            if (!user) {
                return reply(Boom.unauthorized());
            }

            Bcrypt.compare(password, user.password, (err, valid) => {

                if (err) {
                    throw err;
                }

                if (!valid) {
                    return reply(Boom.unauthorized());
                }

                if (tfa || user.requireTfa) {
                    return reply.redirect('/authy').state('authy', {
                        email: email,
                        authyId: user.authyId
                    });
                }

                request.auth.session.set(user);
                return reply.redirect('/');
            });
        }
    });

    server.start(() => {

        console.log('Started server');
    });
});
