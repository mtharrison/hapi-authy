'use strict';

const Hapi = require('hapi');
const Joi = require('joi');
const Path = require('path');
const User = require('./user');

const server = new Hapi.Server();
server.connection({ port: 4000 });

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
        registerFunc: function (request, reply) {

            reply.view('register', { path: request.path });
        },
        verifyFunc: function (request, reply) {

            reply.view('verify', {
                path: request.path,
                smsPath: request.plugins.authy.smsPath
            });
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

                User.setTFA(credentials.email, credentials.authyId, (err, user) => {

                    if (err) {
                        throw err;
                    }

                    request.auth.session.set(user);
                    return reply.redirect('/');
                });
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

            User.validatePassword(email, password, (err, valid, user) => {

                if (err) {
                    throw err;
                }

                if (!valid) {
                    return reply.view('login');
                }

                if (tfa || user.require_2fa) {
                    return reply.redirect('/authy')
                        .state('authy', {
                            email: user.email, authyId: user.authy_id
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
