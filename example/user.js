'use strict';

const Bcrypt = require('bcryptjs');
const Path = require('path');
const Sqlite3 = require('sqlite3');
const db = new Sqlite3.Database(Path.join(__dirname, 'db.sqlite'));


const internals = {};


exports.get = internals.get = function (email, callback) {

    db.get('SELECT * FROM users WHERE email = ?', email, callback);
};


exports.validatePassword = function (email, password, callback) {

    internals.get(email, (err, user) => {

        if (err) {
            return callback(err);
        }

        Bcrypt.compare(password, user.password, (err, valid) => {

            callback(err, valid, user);
        });
    });
};


exports.setTFA = function (email, authyId, callback) {

    internals.get(email, (err, user) => {

        if (err) {
            return callback(err);
        }

        db.run('UPDATE users SET authy_id = ?, require_2fa = 1 WHERE id = ?',
            [authyId, user.id], (err) => {

                return callback(err, user);
            });
    });
};
