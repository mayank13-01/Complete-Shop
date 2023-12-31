const express = require("express");
const { check, body } = require("express-validator");

const User = require("../models/user");

const router = express.Router();

const authController = require("../controllers/auth");

router.get("/login", authController.getLogin);

router.get("/signup", authController.getSignup);

router.get("/reset", authController.getReset);

router.get("/reset/:token", authController.getNewPassword);

router.post(
  "/login",
  body("email")
    .isEmail()
    .withMessage("Invalid Email")
    .custom((value, { req }) => {
      return User.findOne({ email: value }).then((user) => {
        if (!user) {
          return Promise.reject("Email Not Found");
        }
      });
    })
    .normalizeEmail(),
  body("password").trim(),
  authController.postLogin
);

router.post(
  "/signup",
  check("email")
    .isEmail()
    .withMessage("Invalid Email")
    .custom((value, { req }) => {
      return User.findOne({ email: value }).then((userDoc) => {
        if (userDoc) {
          return Promise.reject("Email Already Exists");
        }
      });
    })
    .normalizeEmail(),
  body("password")
    .isStrongPassword()
    .withMessage("Enter a Valid Password")
    .trim(),
  body("confirmPassword")
    .trim()
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords do not Match");
      }
      return true;
    }),
  authController.postSignup
);

router.post("/logout", authController.postLogout);

router.post("/reset", authController.postReset);

router.post("/new-password", authController.postNewPassword);

module.exports = router;
