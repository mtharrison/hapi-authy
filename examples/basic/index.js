'use strict';

const Boom = require('boom');
const Bcrypt = require('bcryptjs');
const Hapi = require('hapi');
const Joi = require('joi');
const Path = require('path');

const server = new Hapi.Server();
server.connection({ port: 4000 });

const users = {
    'hi@matt-harrison.com': {
        password: '$2a$08$.sI.S6l9lL0crviIOn/EUuAc/0oTlBA9R0b6rGEJYRD2p2h76bKK.', // 'secret'
        requireTfa: false,
        authyId: null
    }
};

server.register([
    { register: require('vision') },
    { register: require('hapi-auth-cookie') },
    { register: require('../..') }
], (err) => {

    if (err) {
        throw err;
    }

    server.views({
        engines: {
            hbs: require('handlebars')
        },
        path: Path.join(__dirname, 'templates'),
        layout: true
    });

    // Email/password login stage

    server.auth.strategy('session', 'cookie', {
        password: 'password',
        cookie: 'sid-example',
        redirectTo: '/login',
        isSecure: false
    });

    server.route([{
        method: 'GET',
        path: '/',
        config: {
            auth: 'session',
            handler: {
                view: 'index'
            }
        }
    }, {
        method: 'GET',
        path: '/login',
        handler: {
            view: 'login'
        }
    }, {
        method: 'POST',
        path: '/login',
        config: {
            validate: {
                payload: {
                    email: Joi.string().email().required(),
                    password: Joi.string().required(),
                    enableTfa: Joi.boolean().default(false)
                }
            }
        },
        handler: function (request, reply) {

            const email = request.payload.email;
            const password = request.payload.password;
            const user = users[email];

            if (!user) {
                return reply(Boom.unauthorized());
            }

            Bcrypt.compare(password, user.password, (err, valid) => {

                if (err || !valid) {
                    return reply(Boom.unauthorized());
                }

                if (request.payload.enableTfa || user.requireTfa) {
                    return reply.redirect('/authy').state('authy', {
                        email: email,
                        authyId: user.authyId
                    });
                }

                request.auth.session.set(user);
                return reply.redirect('/');
            });
        }
    }]);

    // Authy 2FA stage

    server.auth.strategy('authy', 'authy', {
        apiKey: 'AUTHY_API_KEY',
        sandbox: false,
        cookieOptions: {
            isSecure: false,
            path: '/',
            encoding: 'iron',
            password: 'password'
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

    server.start(() => {

        console.log('Started server');
    });
});
