import { registerSchema, loginSchema } from "./auth.schema";
import { Request, Response } from "express";
import { User } from "../../models/user.model";
import { hashPassword, comparePassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import { generateAccessToken, generateRefreshToken, verifyRefreshToken } from "../../lib/token";
import crypto from "crypto";

function getAppUrl() {
    if (process.env.NODE_ENV === "development") {
        return `http://localhost:${process.env.PORT}`;
    }
    return process.env.APP_URL! || `http://localhost:${process.env.PORT}`;
}

export async function registerHandler(req: Request, res: Response) {
    try {
        const result = registerSchema.safeParse(req.body);
        if (!result.success) {
            return res.status(400).json({ message: "Invalid data", error: result.error.flatten() });
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
        const verifyToken = jwt.sign({ id: newUser._id }, process.env.JWT_ACCESS_SECRET!, { expiresIn: "1d" });

        const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

        await sendEmail(
            email,
            "Verify your email",
            `<p>Please click on the link below to verify your email:</p>
            <p><a href="${verifyUrl}">Verify Email</a></p>`
        );

        return res.status(201).json({
            message: "User registered successfully", user: {
                name,
                email,
                role: newUser.role,
                isEmailVerified: newUser.isEmailVerified,
            }
        });

    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }

}

export async function verifyEmailHandler(req: Request, res: Response) {
    const token = req.query.token as string || undefined;

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
            return res.status(400).json({ message: "Invalid data", error: result.error.flatten() });
        }
        const { email, password } = result.data;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        const isPasswordValid = await comparePassword(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid password" });
        }

        if (!user.isEmailVerified) {
            return res.status(401).json({ message: "Please verify your email before logging in" });
        }

        const accessToken = generateAccessToken(String(user._id), user.role, user.tokenVersion);
        const refreshToken = generateRefreshToken(String(user._id), user.tokenVersion);

        const isProduction = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: isProduction,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
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
            }
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

        const newAccessToken = generateAccessToken(String(user._id), user.role, user.tokenVersion);

        const newRefreshToken = generateRefreshToken(String(user._id), user.tokenVersion);
        const isProduction = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: isProduction,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
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
            }
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
            return res.json({ message: "If an account with this email exists, we'll send you a link to reset your password." });
        }

        const rawToken = crypto.randomBytes(32).toString("hex");
        const token = crypto.createHash("sha256").update(rawToken).digest("hex");
        user.resetPasswordToken = token;
        user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);
        await user.save();

        const resetUrl = `${getAppUrl()}/auth/reset-password?token=${token}`;

        await sendEmail(
            user.email,
            "Reset Password",
            `Click <a href="${resetUrl}">here</a> to reset your password`
        )

        return res.json({ message: "If an account with this email exists, we'll send you a link to reset your password." });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }

}