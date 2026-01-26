import { registerSchema } from "./auth.schema";
import { Request, Response } from "express";
import { User } from "../../models/user.model";
import { hashPassword } from "../../lib/hash";
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
            `Please click on the link below to verify your email: <a href="${verifyUrl}">Verify Email</a>`
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