import { registerSchema, loginSchema } from "./auth.schema";
import { Request, Response } from "express";
import { User } from "../../models/user.model";
import { hashPassword, comparePassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";

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
    } catch (error) {
        
    }
}