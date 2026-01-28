import { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../lib/token";
async function requreAuth(req: Request, res: Response, next: NextFunction) {
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

        } catch (error) {
            return res.status(401).json({ message: "Unauthorized! You are not authenticated" });
        }
    } catch (error) {

    }
}