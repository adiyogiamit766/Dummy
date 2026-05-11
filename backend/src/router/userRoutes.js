const express = require("express");
const {
  register,
  login,
  refreshToken,
  logout,
  logoutAll,
  verifyEmail,
} = require("../controller/auth");
const router = express.Router();

router.post("/register", register);

router.post("/login", login);

router.get("/refresh-token", refreshToken);

router.get("/logout", logout);

router.get("/logout-all", logoutAll);

router.get("/verify-email", verifyEmail);

module.exports = router;
