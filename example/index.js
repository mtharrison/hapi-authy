var Bcrypt = require('bcrypt');

var Hapi = require('hapi');
var Joi = require('joi');
var Path = require('path');
var User = require('./user');

var server = new Hapi.Server();
server.connection({ port: 4000 });

server.register([
    { register: require('vision') },
    { register: require('hapi-auth-cookie') },
    { register: require('./authy') },
], function (err) {

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
        apiKey: 'jkdsVwp8503GNcAqMLC2GToxj1EXq3Yq',
        sandbox: false
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
        method: ['GET', 'POST'],
        path: '/authy',
        config: {
            auth: {
                strategies: ['authy'],
                payload: true
            },
            handler: function (request, reply) {

                var credentials = request.auth.credentials;
                
                User.setTFA(credentials.email, credentials.authyId, function (err, user) {

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

            var email = request.payload.email;
            var password = request.payload.password;
            var tfa = request.payload.tfa;

            User.validatePassword(email, password, function (err, valid, user) {

                if (err) {
                    throw err;
                }

                if (!valid) {
                    return reply.view('login');
                }

                if (request.payload.tfa || user.require_2fa) {
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
    
    server.start(function () {
        console.log('Started server');
    });
});