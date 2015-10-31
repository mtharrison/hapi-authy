'use strict';

// Load modules

const Code = require('code');
const Hapi = require('hapi');
const Iron = require('iron');
const Lab = require('lab');
const Path = require('path');


// Declare internals

const internals = {
    password: 'Q3QJIcIIvKcMwG7c'
};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;
const beforeEach = lab.beforeEach;


internals.makeCookie = function (obj, callback) {

    Iron.seal(obj, internals.password, Iron.defaults, (err, sealed) => {

        callback(sealed);
    });
};


internals.mockClient = function () {

    return {
        request_sms: function (id, callback) {

            callback();
        },
        register_user: function (email, phone, country, sms, callback) {

            callback(internals.clientError, {
                user: { id: 123456 }
            });
        },
        verify: function (id, token, callback) {

            callback(internals.clientError, {
                user: { id: 123456 }
            });
        }
    };
};


describe('hapi-authy', () => {

    let server;

    beforeEach((done) => {

        internals.clientError = null;

        server = new Hapi.Server();
        server.connection({ port: 4000 });
        server.register(require('vision'), (err) => {});
        server.register(require('../'), (err) => {});

        server.auth.strategy('authy', 'authy', {
            apiKey: 'aDfI6YR2qFF6Klsl6eEJTBLqAfphO9AG',
            sandbox: false,
            cookieOptions: {
                isSecure: false,
                path: '/',
                encoding: 'iron',
                password: 'Q3QJIcIIvKcMwG7c'
            },
            client: internals.mockClient
        });

        server.views({
            engines: {
                hbs: require('handlebars')
            },
            path: Path.join(__dirname, 'templates')
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

                    reply('SUCESS!');
                }
            }
        });

        done();
    });

    it('expects an cookie to be set', (done) => {

        server.inject('/authy', (res) => {

            expect(res.statusCode).to.equal(401);
            expect(res.result.message).to.equal('Missing authy cookie');
            done();
        });
    });

    it('passes through when verified', (done) => {

        const obj = {
            email: 'bob@jones.com',
            authyId: 123456,
            verified: true
        };

        internals.makeCookie(obj, (cookie) => {

            server.inject({
                method: 'GET',
                url: 'http://localhost:4000/authy',
                headers: {
                    cookie: 'authy=' + cookie
                }
            }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('SUCESS!');
                done();
            });
        });
    });

    it('can be set to sandbox', (done) => {

        server.auth.strategy('authy2', 'authy', {
            apiKey: 'aDfI6YR2qFF6Klsl6eEJTBLqAfphO9AG',
            sandbox: true,
            cookieName: 'authy2',
            requestTokenUrl: '/request',
            cookieOptions: {
                isSecure: false,
                path: '/',
                encoding: 'iron',
                password: 'Q3QJIcIIvKcMwG7c'
            },
            client: internals.mockClient
        });

        server.inject('/authy', (res) => {

            expect(res.statusCode).to.equal(401);
            expect(res.result.message).to.equal('Missing authy cookie');
            done();
        });
    });

    it('prompts for registration if required', (done) => {

        const obj = {
            email: 'bob@jones.com',
            authyId: null
        };

        internals.makeCookie(obj, (cookie) => {

            server.inject({
                method: 'GET',
                url: 'http://localhost:4000/authy',
                headers: {
                    cookie: 'authy=' + cookie
                }
            }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('register');
                done();
            });
        });
    });

    it('prompts for verification if required', (done) => {

        const obj = {
            email: 'bob@jones.com',
            authyId: 123456
        };

        internals.makeCookie(obj, (cookie) => {

            server.inject({
                method: 'GET',
                url: 'http://localhost:4000/authy',
                headers: {
                    cookie: 'authy=' + cookie
                }
            }, (res) => {

                expect(res.statusCode).to.equal(200);
                expect(res.result).to.equal('verify');
                done();
            });
        });
    });

    it('performs registration on proper payload', (done) => {

        const obj = {
            email: 'bob@jones.com',
            authyId: null
        };

        internals.makeCookie(obj, (cookie) => {

            server.inject({
                method: 'POST',
                url: 'http://localhost:4000/authy',
                headers: {
                    cookie: 'authy=' + cookie
                },
                payload: JSON.stringify({ country: '1', phone: '123546789' })
            }, (res) => {

                expect(res.statusCode).to.equal(302);
                done();
            });
        });
    });

    it('fails registration on client error', (done) => {

        internals.clientError = new Error('error');

        const obj = {
            email: 'bob@jones.com',
            authyId: null
        };

        internals.makeCookie(obj, (cookie) => {

            server.inject({
                method: 'POST',
                url: 'http://localhost:4000/authy',
                headers: {
                    cookie: 'authy=' + cookie
                },
                payload: JSON.stringify({ country: '1', phone: '123546789' })
            }, (res) => {

                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('fails registration on bad payload', (done) => {

        const obj = {
            email: 'bob@jones.com',
            authyId: null
        };

        internals.makeCookie(obj, (cookie) => {

            server.inject({
                method: 'POST',
                url: 'http://localhost:4000/authy',
                headers: {
                    cookie: 'authy=' + cookie
                },
                payload: JSON.stringify({ a: 1 })
            }, (res) => {

                expect(res.statusCode).to.equal(401);
                expect(res.result.message).to.equal('Could\'t register user');
                done();
            });
        });
    });

    it('performs verification on proper payload', (done) => {

        const obj = {
            email: 'bob@jones.com',
            authyId: 123456
        };

        internals.makeCookie(obj, (cookie) => {

            server.inject({
                method: 'POST',
                url: 'http://localhost:4000/authy',
                headers: {
                    cookie: 'authy=' + cookie
                },
                payload: JSON.stringify({ token: '1234567' })
            }, (res) => {

                expect(res.statusCode).to.equal(302);
                done();
            });
        });
    });

    it('fails verification on client error', (done) => {

        internals.clientError = new Error('error');

        const obj = {
            email: 'bob@jones.com',
            authyId: 123456
        };

        internals.makeCookie(obj, (cookie) => {

            server.inject({
                method: 'POST',
                url: 'http://localhost:4000/authy',
                headers: {
                    cookie: 'authy=' + cookie
                },
                payload: JSON.stringify({ token: '1234567' })
            }, (res) => {

                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('fails verification on bad payload', (done) => {

        const obj = {
            email: 'bob@jones.com',
            authyId: 123456
        };

        internals.makeCookie(obj, (cookie) => {

            server.inject({
                method: 'POST',
                url: 'http://localhost:4000/authy',
                headers: {
                    cookie: 'authy=' + cookie
                },
                payload: JSON.stringify({ a: 1 })
            }, (res) => {

                expect(res.statusCode).to.equal(401);
                expect(res.result.message).to.equal('Could\'t validate token');
                done();
            });
        });
    });

    it('can request a token', (done) => {

        const obj = {
            email: 'bob@jones.com',
            authyId: 123456
        };

        internals.makeCookie(obj, (cookie) => {

            server.inject({
                url: '/authy-request-token',
                headers: {
                    cookie: 'authy=' + cookie
                }
            }, (res) => {

                expect(res.statusCode).to.equal(302);
                done();
            });
        });
    });

    it('request.plugins doesn\'t get clobbered', (done) => {

        server.ext('onPreAuth', (request, reply) => {

            request.plugins.authy = { a: 1 };
            reply.continue();
        });

        server.inject('/authy', (res) => {

            expect(res.statusCode).to.equal(401);
            expect(res.result.message).to.equal('Missing authy cookie');
            done();
        });
    });
});
