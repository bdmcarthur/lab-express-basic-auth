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
