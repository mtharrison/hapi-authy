var Bcrypt = require('bcrypt');
var Path = require('path');
var Sqlite3 = require('sqlite3');

var db = new Sqlite3.Database(Path.join(__dirname, 'db.sqlite'));

var internals = {};


exports.get = internals.get = function (email, callback) {

    db.get('SELECT * FROM users WHERE email = ?', email, callback);
};


exports.validatePassword = function (email, password, callback) {

    internals.get(email, function (err, user) {

        if (err) {
            return callback(err);
        }

        Bcrypt.compare(password, user.password, function (err, valid) {

            callback(err, valid, user);
        });
    });
};


exports.setTFA = function (email, authyId, callback) {

    internals.get(email, function (err, user) {

        if (err) {
            return callback(err);
        }

        db.run('UPDATE users SET authy_id = ?, require_2fa = 1 WHERE id = ?', 
            [authyId, user.id], function (err) {

            return callback(err, user);
        });
    });
};