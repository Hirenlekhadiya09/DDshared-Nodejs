const express = require("express");
const {
  registerUser,
  verifyUser,
  resendOtp,
  loginUser,
  forgotPassword,
  verifyForgotPassword,
  resetPassword,
  LoginWithAuth,
} = require("../controller/user");

const router = express.Router();

router.post("/register", registerUser);
router.post("/verifyAccount", verifyUser);
router.put("/resendOtp", resendOtp);
router.post("/login", loginUser);
router.put("/forgotPassword", forgotPassword);
router.put("/forgotResendOtp", forgotPassword);
router.put("/verifyForgotPassword", verifyForgotPassword);
router.put("/resetPassword", resetPassword);
// router.post("/loginWithAuth", LoginWithAuth);

// router.get(
//   "/auth/facebook",
//   passport.authenticate("facebook", { scope: "email" })
// );

// router.get(
//   "/auth/facebook/callback",
//   passport.authenticate("facebook", {
//     successRedirect: "/profile",
//     failureRedirect: "/fail",
//   })
// );

router.get("/fail", (req, res) => {
  res.send("Failed attempt");
});

router.get("/", (req, res) => {
  res.send("Success done !");
});

module.exports = router;
