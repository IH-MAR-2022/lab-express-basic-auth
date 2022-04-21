const router = require("express").Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User.model");
const saltRound = 10;
const isLoggedIn = require("../middleware/isLoggedIn");

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

//GET signup
router.get("/signup", (req, res, next) => {
  res.render("signup");
});

//POST signup

router.post("/signup", (req, res, next) => {
  //1. Make sure fields are filled out
  if (!req.body.username || !req.body.password) {
    res.render("signup", { message: "Username/password required" });
  }

  //2. Make sure Username is not taken
  User.findOne({ username: req.body.username })
    .then((foundUser) => {
      if (foundUser) {
        res.render("signup", { message: "Username is already taken" });
      }

      //3. Hash the password
      const salt = bcrypt.genSaltSync(saltRound); //saltRound is 10
      const hashPass = bcrypt.hashSync(req.body.password, salt);

      //4. Create the User
      User.create({
        username: req.body.username,
        password: hashPass,
      })
        .then((results) => {
          res.redirect("/");
        })
        .catch((error) => {
          console.log("Failed creating user", error.messagfe);
        });
    })
    .catch((error) => {
      console.log("Failed while searching users", error.message);
    });
});

//GET login
router.get("/login", (req, res, next) => {
  res.render("login");
});

//POST login
router.post("/login", (req, res, next) => {
  //1. Make sure fields are filled out
  if (!req.body.username || !req.body.password) {
    res.render("signup", { message: "Username/password required" });
  }

  //2. Make sure Username is not taken
  User.findOne({ username: req.body.username })
    .then((foundUser) => {
      if (!foundUser) {
        res.render("signup", { message: "Username not found" });
      } else {
        //compare password to hashed password
        const doesMatch = bcrypt.compareSync(
          req.body.password,
          foundUser.password
        );

        if (doesMatch) {
          req.session.user = foundUser;
          res.render("index", { info: JSON.stringify(req.session) });
        } else {
          res.render("signup", { message: "Password is incorrect" });
        }
      }
    })
    .catch((error) => {
      console.log("Failed", error.message);
    });
});

//GET secret
router.get("/secret", isLoggedIn, (req, res, next) => {
  //1.Check to see if you are logged in
  res.render("secret");
});

router.get("/secret2", isLoggedIn, (req, res, next) => {
  res.render("secret2");
});

//GET logout
router.get("/logout", (req, res, next) => {
  req.session.destroy();
  res.render("index", { info: "You have logged out" });
});

module.exports = router;
