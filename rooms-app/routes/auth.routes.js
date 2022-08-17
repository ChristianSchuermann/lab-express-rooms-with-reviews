const router = require("express").Router();
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const saltRounds = 10;
const User = require("../models/User.model");
const isLoggedOut = require("../middleware/isLoggedOut");
const isLoggedIn = require("../middleware/isLoggedIn");

router.get("/signup", isLoggedOut, (req, res) => {
  res.render("auth/signup");
});

router.post("/signup", isLoggedOut, (req, res) => {
  const { username, password } = req.body;

  if (!username) {
    return res.render("auth/signup", {
      errorMessage: "Enter a username",
    });
  }

  if (password.length < 8) {
    return res.render("auth/signup", {
      errorMessage: "Password needs to be at least 8 characters long.",
    });
  }

  User.findOne({ username }).then((found) => {
    if (found) {
      return res.render("auth.signup", { errorMessage: "Username already in use" });
    }

    return bcrypt
    .genSalt(saltRounds)
    .then((salt) => bcrypt.hash(password, salt))
    .then((hashedPassword) => {
      console.log(hashedPassword);
      return User.create({
        username,
        email,
        passwordHash: hashedPassword,
      });
    })
    .then((user) => {
      console.log(user.username);

      res.render("auth/profile", { user });
    })
    .catch((error) => console.log(error));

});

  });

router.get("/login", isLoggedOut, (req, res) => {
  res.render("auth/login");
});

router.post("/login", isLoggedOut, (req, res, next) => {
  const { username, password } = req.body;

  if (!username) {
    return res.render("auth/login", {
      errorMessage: "Please enter a username.",
    });
  }

  if (password.length < 8) {
    return res.render("auth/login", {
      errorMessage: "Your password needs to be at least 8 characters long.",
    });
  }


  User.findOne({ username })
    .then((user) => {
      if (!user) {
        return res.render("auth/login", {
          errorMessage: "wrong password or username",
        });
      }

      bcrypt.compare(password, user.password).then((isSamePassword) => {
        if (!isSamePassword) {
          return res.render("auth/login", {
            errorMessage: "wrong password or username",
          });
        }
        req.session.user = user;
        return res.redirect("/");
      });
    })

    .catch((err) => {next(err);});
});

router.get("/logout", isLoggedIn, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.render("auth/logout", { errorMessage: err.message });
    }
    res.redirect("/");
  });
});

module.exports = router;