const express = require("express");
const models = require("../models/index");
const bcrypt = require('bcrypt');
const passport = require('passport');

const router = express.Router();

const isAuthenticated = function(req, res, next) {
  // console.log(req.isAuthenicated());
  if (req.isAuthenticated()) {
    // req.session = User
    return next()
  }
  req.flash('error', 'You have to be logged in to access the page.')
  res.redirect('/')
}

// user needs to still be logged in for them to have access to it
const requireLogin = function(req, res, next) {
  if(req.user){
    console.log('REQ USER',req.user);
    next();
  } else {
    res.redirect('/');
  }
};

// requires user to login in to access infor
const login = function(req, res, next) {
  if (req.user) {
    res.redirect('/homepage')
  } else {
    next();
  }
};

router.get('/', login, function(req, res) {
  res.render('login');
});

router.post('/', login, passport.authenticate('local', {
  successRedirect: '/homepage',
  failureRedirect: '/',
  failureFlash: true
}));

router.get('/signup', function(req, res) {
  res.render('signup');
});

router.post('/signup', function(req, res) {
  let name = req.body.name
  let username = req.body.username
  let password = req.body.password
  let passwordconfirm = req.body.passwordconfirm
  let match = false;

  if (!username || !password) {
    req.flash('error', 'Please, fill in all the fields.')
    res.redirect('signup')
  } else if (password != passwordconfirm) {
      match = true;
      req.flash('error', 'Please, make sure your passsword matches.')
      res.redirect('signup')
  }

  let salt = bcrypt.genSaltSync(10)
  let hashedPassword = bcrypt.hashSync(password, salt)

  let newuser = {
    name: name,
    username: username,
    salt: salt,
    password: hashedPassword
  }

  models.user.create(newuser)
  .then(function() {
    res.redirect('/')
  })
  .catch(function(error) {
    req.flash('error', 'Please, choose a different username.')
    res.redirect('signup')
  });
});

router.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
});

module.exports = router;
