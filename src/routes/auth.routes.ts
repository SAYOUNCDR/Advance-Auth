import { Router } from "express";
import {
    registerHandler,
    loginHandler,
    verifyEmailHandler,
    refreshHandler,
    logOutHandler,
    forgotPasswordHandler,
    resetPasswordHandler,
    googleAuthStartHandler,
    googleAuthcallbackHandler,
    twoFASetupHandler,
    twoFAVerifyHandler
} from "../controllers/auth/auth.controller";

import requireAuth from "../middleware/requireAuth"

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
router.post("/2fa/setup", requireAuth, twoFASetupHandler)
router.post("/2fa/verify", requireAuth, twoFAVerifyHandler)

export default router
