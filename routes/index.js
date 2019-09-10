'use strict';

const { Router } = require('express');
const router = Router();
const bcrypt = require("bcrypt");
const User = require("../models/user");

const routeGuardMiddleware = (req, res, next) => {
  if (!req.session.user) {
    res.redirect('/authentication/sign-up');
  } else {
    next();
  }
};

router.get('/', (req, res, next) => {
  res.render('index', { title: 'Hello World!' });
});

router.get('/authentication/sign-up', (req, res, next) => {
  res.render('sign-up');
});


const bcryptSalt = 10;
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

router.get('/authentication/profile', routeGuardMiddleware, (req, res, next) => {
  const id = req.session.user._id
  User.findById(id)
    .then(user => {
      res.render("profile", {user: user});
    })
    .catch(err => {
      console.log("err");
    });
});

router.get('/authentication/profile-edit', routeGuardMiddleware, (req, res, next) => {
  res.render('profile-edit');
});

router.post('/authentication/profile-edit', routeGuardMiddleware, (req, res, next) => {
  const username = req.body.username;
  const name = req.body.name;

  User.update({username: username}, { $set: {name: name}})
  .then((book) => {
    res.redirect('/authentication/profile');
  })
  .catch((error) => {
    console.log(error);
  })
});

router.get('/authentication/main', routeGuardMiddleware, (req, res, next) => {
  res.render('main');
});

router.get('/authentication/private', routeGuardMiddleware, (req, res, next) => {
  res.render('private');
});

router.post('/authentication/sign-out', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

module.exports = router;
