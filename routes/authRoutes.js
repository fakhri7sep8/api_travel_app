const express = require("express");
const authController = require("../controllers/authControllers");
const router = express.Router();

router.post("/register", authController.register);
router.post("/verify", authController.verify);
router.post("/login", authController.login);
router.post("/forgot-password", authController.forgotPassword);

module.exports = router;