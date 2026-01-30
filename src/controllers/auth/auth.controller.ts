import { registerSchema, loginSchema } from "./auth.schema";
import { sendEmail } from "../../lib/email";
import { Request, Response } from "express";
import { User } from "../../models/user.model";
import { hashPassword, comparePassword } from "../../lib/hash";
import {
    generateAccessToken,
    generateRefreshToken,
    verifyRefreshToken,
} from "../../lib/token";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";
import { generateSecret, generate, verify, generateURI } from "otplib";

function getAppUrl() {
    if (process.env.NODE_ENV === "development") {
        return `http://localhost:${process.env.PORT}`;
    }
    return process.env.APP_URL! || `http://localhost:${process.env.PORT}`;
}

function getGoogleClinet() {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const redirectUri = process.env.GOOGLE_REDIRECT_URI;

    if (!clientId || !clientSecret || !redirectUri) {
        throw new Error("Google client ID, client secret, or redirect URI not found");
    }
    return new OAuth2Client({ clientId, clientSecret, redirectUri });
}

export async function registerHandler(req: Request, res: Response) {
    try {
        const result = registerSchema.safeParse(req.body);
        if (!result.success) {
            return res
                .status(400)
                .json({ message: "Invalid data", error: result.error.flatten() });
        }
        const { name, email, password } = result.data;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await hashPassword(password);

        const newUser = await User.create({
            name,
            email,
            password: hashedPassword,
            role: "user",
            isEmailVerified: false,
            twoFactorEnabled: false,
        });

        // Email verification logic
        const verifyToken = jwt.sign(
            { id: newUser._id },
            process.env.JWT_ACCESS_SECRET!,
            { expiresIn: "1d" },
        );

        const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

        await sendEmail(
            email,
            "Verify your email",
            `<p>Please click on the link below to verify your email:</p>
            <p><a href="${verifyUrl}">Verify Email</a></p>`,
        );

        return res.status(201).json({
            message: "User registered successfully",
            user: {
                name,
                email,
                role: newUser.role,
                isEmailVerified: newUser.isEmailVerified,
            },
        });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}

export async function verifyEmailHandler(req: Request, res: Response) {
    const token = (req.query.token as string) || undefined;

    if (!token) {
        return res.status(400).json({ message: "Invalid token" });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
            id: string;
        };

        const user = await User.findById(payload.id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        if (user.isEmailVerified) {
            return res.status(400).json({ message: "Email already verified" });
        }
        user.isEmailVerified = true;
        await user.save();
        return res.status(200).json({ message: "Email verified successfully" });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}

export async function loginHandler(req: Request, res: Response) {
    try {
        const result = loginSchema.safeParse(req.body);
        if (!result.success) {
            return res
                .status(400)
                .json({ message: "Invalid data", error: result.error.flatten() });
        }
        const { email, password, twoFactorCode } = result.data;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        const isPasswordValid = await comparePassword(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid password" });
        }

        if (!user.isEmailVerified) {
            return res
                .status(401)
                .json({ message: "Please verify your email before logging in" });
        }


        if (user.twoFactorEnabled) {
            if (!twoFactorCode || typeof twoFactorCode !== 'string') {
                return res.status(400).json({ message: "2FA code is required" });
            }
            if (!user.twoFactorSecret) {
                return res.status(400).json({ message: "2FA misconfigured" });
            }

            const verificationResult: any = await verify({
                secret: user.twoFactorSecret,
                token: twoFactorCode
            }); // This returns an object with valid and epoch properties example { valid: true, epoch: 1738222222 }
            // What is epoch? It is the number of seconds since the Unix epoch (January 1, 1970, 00:00:00 UTC).

            const isValidCode = typeof verificationResult === 'object' && verificationResult !== null
                ? verificationResult.valid
                : verificationResult; // This returns true or false, true if the code is valid, false otherwise

            // This checks if the 2FA code is valid
            if (!isValidCode) {
                return res.status(400).json({ message: "Invalid 2FA code" });
            }
        }

        const accessToken = generateAccessToken(
            String(user._id),
            user.role,
            user.tokenVersion,
        );
        const refreshToken = generateRefreshToken(
            String(user._id),
            user.tokenVersion,
        );

        const isProduction = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: isProduction,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.status(200).json({
            message: "Login successful",
            accessToken,
            user: {
                name: user.name,
                email: user.email,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                twoFactorEnabled: user.twoFactorEnabled,
            },
        });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}

export async function refreshHandler(req: Request, res: Response) {
    try {
        const token = req.cookies?.refreshToken as string | undefined;

        if (!token) {
            return res.status(401).json({ message: "Refresh token missing" });
        }
        const payload = verifyRefreshToken(token);
        if (!payload) {
            return res.status(401).json({ message: "Invalid refresh token" });
        }

        const user = await User.findById(payload.id);

        if (!user) {
            return res.status(400).json({ message: "User not found" });
        }
        if (user.tokenVersion !== payload.tokenVersion) {
            return res.status(401).json({ message: "Invalid refresh token" });
        }

        const newAccessToken = generateAccessToken(
            String(user._id),
            user.role,
            user.tokenVersion,
        );

        const newRefreshToken = generateRefreshToken(
            String(user._id),
            user.tokenVersion,
        );
        const isProduction = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: isProduction,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.status(200).json({
            message: "Refresh token successful",
            accessToken: newAccessToken,
            user: {
                name: user.name,
                email: user.email,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                twoFactorEnabled: user.twoFactorEnabled,
            },
        });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}

// Note For frontend after the cookie is cleared the user should redirect to login page
// Another important Note: This logout handler is not fullproof as if cookie is stolen and user logs out from current device but attacker has refresh token to generate new access token and refresh token and can access the protected routes
export async function logOutHandler(req: Request, res: Response) {
    try {
        res.clearCookie("refreshToken", { path: "/" });
        return res.status(200).json({ message: "Logout successful" });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}

export async function forgotPasswordHandler(req: Request, res: Response) {
    const { email } = req.body as { email: string };
    try {
        const normalizedEmail = email.toLowerCase().trim();
        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.json({
                message:
                    "If an account with this email exists, we'll send you a link to reset your password.",
            });
        }

        const rawToken = crypto.randomBytes(32).toString("hex");
        const token = crypto.createHash("sha256").update(rawToken).digest("hex");
        user.resetPasswordToken = token;
        user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);
        await user.save();

        const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;

        await sendEmail(
            user.email,
            "Reset Password",
            `Click <a href="${resetUrl}">here</a> to reset your password`,
        );

        return res.json({
            message:
                "If an account with this email exists, we'll send you a link to reset your password.",
        });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}

export async function resetPasswordHandler(req: Request, res: Response) {
    const { token, password } = req.body as { token: string; password: string };
    if (!token) {
        return res.status(400).json({ message: "Token is required" });
    }
    if (!password || password.length < 6) {
        return res.status(400).json({
            message: "Password is required and must be at least 6 characters long",
        });
    }


    try {
        const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

        const user = await User.findOne({
            resetPasswordToken: tokenHash,
            resetPasswordExpires: { $gt: Date.now() }, // this is to check if the token is expired
        });
        if (!user) {
            return res.status(400).json({ message: "Invalid token" });
        }

        const newPasswordHash = await hashPassword(password);
        user.password = newPasswordHash;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        user.tokenVersion += 1; // this is to invalidate all the previous tokens
        await user.save();

        return res.json({ message: "Password reset successful" });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}


export async function googleAuthStartHandler(req: Request, res: Response) {
    try {
        const client = getGoogleClinet();
        const url = client.generateAuthUrl({
            access_type: "offline",
            prompt: "consent",
            scope: ["openid", "profile", "email"],
        });
        return res.redirect(url);
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}

export async function googleAuthcallbackHandler(req: Request, res: Response) {
    try {
        const code = req.query.code as string | undefined;
        if (!code) {
            return res.status(400).json({ message: "Code is required" });
        }
        try {
            const client = getGoogleClinet();

            const { tokens } = await client.getToken(code);

            if (!tokens.id_token) {
                return res.status(400).json({ message: "Invalid code" });
            }

            const ticket = await client.verifyIdToken({
                idToken: tokens.id_token,
                audience: process.env.GOOGLE_CLIENT_ID as string,
            });

            const payload = ticket.getPayload();
            if (!payload) {
                return res.status(400).json({ message: "Invalid token" });
            }

            const email = payload?.email;
            const emailVerified = payload?.email_verified;

            if (!email || !emailVerified) {
                return res.status(400).json({ message: "Google email account not verified" });
            }

            const normalizedEmail = email.toLowerCase().trim();
            const name = payload.name || `${payload.given_name || ""} ${payload.family_name || ""}`.trim() || "User";

            let user = await User.findOne({ email: normalizedEmail });
            if (!user) {
                const randomPassword = crypto.randomBytes(16).toString("hex");
                const hashedPassword = await hashPassword(randomPassword);
                user = new User({
                    name,
                    email: normalizedEmail,
                    password: hashedPassword,
                    role: "user",
                    isEmailVerified: true,
                    twoFactorEnabled: false,
                });
                await user.save();
            } else {
                if (!user.isEmailVerified) {
                    user.isEmailVerified = true;
                    await user.save();
                }
            }

            const accessToken = generateAccessToken(user.id, user.role as "user" | "admin", user.tokenVersion);
            const refreshToken = generateRefreshToken(user.id, user.tokenVersion);


            const isProduction = process.env.NODE_ENV === "production";
            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: isProduction,
                sameSite: "strict",
                maxAge: 7 * 24 * 60 * 60 * 1000,
            });

            return res.status(200).json({
                message: "Google Login successful",
                accessToken,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role,
                    isEmailVerified: user.isEmailVerified,
                },
            });


        } catch (error) {
            return res.status(500).json({ message: "Internal server error", error });
        }
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}


export async function twoFASetupHandler(req: Request, res: Response) {
    const authReq = req as any;
    const authUser = authReq.user;

    if (!authUser) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    try {
        const user = await User.findById(authUser.id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        if (user.twoFactorEnabled) {
            return res.status(400).json({ message: "2FA is already enabled" });
        }

        const secret = generateSecret();
        const issuer = "NodeAdvanceAuthApp";

        const otpAuthUrl = generateURI({
            secret,
            label: user.email,
            issuer,
        });

        user.twoFactorSecret = secret;
        user.twoFactorEnabled = false;
        await user.save();

        return res.status(200).json({
            message: "2FA setup successful",
            otpAuthUrl,
            secret,
        });

    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}

export async function twoFAVerifyHandler(req: Request, res: Response) {
    const authReq = req as any;
    const authUser = authReq.user;

    if (!authUser) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const { code } = req.body;
    if (!code) {
        return res.status(400).json({ message: "Code is required" });
    }
    try {
        const user = await User.findById(authUser.id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        if (!user.twoFactorSecret) {
            return res.status(400).json({ message: "2FA is not enabled" });
        }

        const verificationResult: any = await verify({
            secret: user.twoFactorSecret,
            token: code as string
        });

        const isValid = typeof verificationResult === 'object' && verificationResult !== null
            ? verificationResult.valid
            : verificationResult;

        if (!isValid) {
            return res.status(400).json({ message: "Invalid code" });
        }

        user.twoFactorEnabled = true;
        await user.save();

        return res.status(200).json({ message: "2FA verification successful", twoFactorEnabled: true });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }
}