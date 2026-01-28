import { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../lib/token";
import { User } from "../models/user.model";


async function requireAuth(req: Request, res: Response, next: NextFunction) {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Unauthorized! You are not authenticated" });
        }

        const token = authHeader.split("Bearer ")[1];
        if (!token) {
            return res.status(401).json({ message: "Unauthorized! You are not authenticated" });
        }

        try {
            const payload = verifyAccessToken(token);

            const user = await User.findById(payload?.id);
            if (!user) {
                return res.status(401).json({ message: "Unauthorized! You are not authenticated" });
            }

            if (user.tokenVersion != payload?.tokenVersion) {
                return res.status(401).json({ message: "Token is expired! Please login again" });
            }

            const authUser = req as any;
            authUser.user = {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                isEmailVerified: user.isEmailVerified
            }
            next();


        } catch (error) {
            return res.status(401).json({ message: "Unauthorized! You are not authenticated" });
        }
    } catch (error) {
        return res.status(401).json({ message: "Unauthorized! You are not authenticated" });
    }
}

export default requireAuth;