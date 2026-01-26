import { registerSchema } from "./auth.schema";
import { Request, Response } from "express";
import { User } from "../../models/user.model";
import { hashPassword } from "../../lib/hash";

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



    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error });
    }

}