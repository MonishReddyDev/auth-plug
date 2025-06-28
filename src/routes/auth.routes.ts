import express from "express";
import {
  githubCallback,
  loginUser,
  logoutAllHandler,
  logoutHandler,
  refreshTokenHandler,
  registerUser,
} from "../controllers/auth.controller";
import { verifyOtpController } from "../controllers/email.controller";
import { validateRequest } from "../middlewares/validateRequest.middleware";
import { loginSchema, registerSchema } from "../validators/auth.validator";
import { resendOtpController } from "../controllers/email.controller";
import {
  forgotPasswordController,
  resetPasswordController,
} from "../controllers/password.controller";
import passport from "../config/passport";
import { googleCallback } from "../controllers/auth.controller";


const router = express.Router();


router.post("/register", validateRequest(registerSchema), registerUser);
router.post("/login", validateRequest(loginSchema), loginUser);
router.post("/refresh", refreshTokenHandler);
router.post("/logout", logoutHandler);
router.post("/logoutAll", logoutAllHandler);

router.post("/verify-otp", verifyOtpController);
router.post("/resend-otp", resendOtpController);

router.post("/forgotPassword", forgotPasswordController);
router.post("/resetPassword", resetPasswordController);

// Redirects user to Google OAuth consent screen
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google redirects back here after user signs in
router.get(
  "/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: "/login",
  }),
  googleCallback // custom logic: issue JWT, set cookies, redirect frontend, etc
);

router.get(
  "/github",
  passport.authenticate("github", { scope: ["user:email"] })
);

router.get(
  "/github/callback",
  passport.authenticate("github", {
    session: false,
    failureRedirect: "/login",
  }),
  githubCallback
);
export default router;
