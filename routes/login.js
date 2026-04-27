const bcrypt = require('bcrypt');
const validator = require('validator');
var log4js = require("log4js");
var url = require("url");
var express = require('express');
var auth = require("../model/auth");
const winston = require('winston'); // 1. Add Winston
var router = express.Router();

// Setup Winston for this file (or import from app.js)
const loggerWinston = winston.createLogger({
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

var logger = log4js.getLogger('vnode');

// Login template
router.get('/login', function(req, res, next) {
    var url_params = url.parse(req.url, true).query;
    res.render('login', {returnurl: url_params.returnurl, auth_error: url_params.error});
});

// Do auth
router.post('/login/auth', async function(req, res) {
    var user = req.body.username;
    var password = req.body.password;
    var returnurl = req.body.returnurl;

    const safeUser = validator.escape(user.trim());

    try {
        const data = await auth(safeUser, password); 
        
        // 2. LOG SUCCESSFUL LOGIN
        loggerWinston.info(`SECURITY SUCCESS: User [${safeUser}] successfully logged in.`);

        req.session.logged = true;
        req.session.user_name = safeUser;

        if (!returnurl || returnurl === ""){
            returnurl = "/";
        }
        res.redirect(returnurl);

    } catch (err) {
        // 3. LOG FAILED LOGIN (Very important for detecting Brute Force)
        loggerWinston.warn(`SECURITY ALERT: Failed login attempt for user: [${safeUser}]`);
        
        res.redirect("/login?returnurl=" + returnurl + "&error=Invalid credentials");
    }
});

// Do logout
router.get('/logout', function(req, res, next) {
    req.session.logged = false;
    req.session.user = null;
    res.redirect("/login")
});

module.exports = router;