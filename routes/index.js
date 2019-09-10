'use strict';

const { Router } = require('express');
const router = Router();
const bcrypt     = require("bcrypt");
const User           = require("../models/user");

router.get('/', (req, res, next) => {
  res.render('index', { title: 'Hello World!' });
});

router.get('/authentication/sign-up', (req, res, next) => {
  res.render('sign-up');
});

router.get('/authentication/log-in', (req, res, next) => {
  res.render('log-in');
});

router.post('/authentication/log-in', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  
  let auxiliaryUser;

  User.findOne({ username })
    .then(user => {
      if (!user) {
        throw new Error('USER_NOT_FOUND');
      } else {
        auxiliaryUser = user;
        return bcrypt.compare(password, user.passwordHash);
      }
    })
    .then(matches => {
      if (!matches) {
        throw new Error('PASSWORD_DOESNT_MATCH');
      } else {
        req.session.user = {
          _id: auxiliaryUser._id
        };
        res.redirect('private');
      }
    })
    .catch(error => {
      console.log('There was an error signing up the user', error);
      next(error);
    });
});






const bcryptSalt     = 10;
router.post('/authentication/sign-up', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const salt     = bcrypt.genSaltSync(bcryptSalt);
  const hashPass = bcrypt.hashSync(password, salt);
 

  User.create({
    username,
    passwordHash: hashPass
  })
  .then(() => {
    res.redirect("/");
  })
  .catch(error => {
    console.log(error);
  })
});

module.exports = router;
