import { Router } from "express";
import { registerHandler, loginHandler, verifyEmailHandler, refreshHandler, logOutHandler, forgotPasswordHandler, resetPasswordHandler, googleAuthStartHandler, googleAuthcallbackHandler } from "../controllers/auth/auth.controller";

const router = Router();


router.post("/register", registerHandler)
router.post("/login", loginHandler)
router.get("/verify-email", verifyEmailHandler)
router.post("/refresh", refreshHandler)
router.post("/logout", logOutHandler)
router.post("/forgot-password", forgotPasswordHandler)
router.post("/reset-password", resetPasswordHandler)
router.get("/google", googleAuthStartHandler)
router.get("/google/callback", googleAuthcallbackHandler)

export default router
