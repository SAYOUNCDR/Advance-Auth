import jwt from "jsonwebtoken";

export function generateAccessToken(userId: string, role: "user" | "admin", tokenVersion: number) {
    const payload = {
        id: userId,
        role,
        tokenVersion
    }
    return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, { expiresIn: "30min" });
}

export function generateRefreshToken(userId: string, tokenVersion: number) {
    const payload = {
        id: userId,
        tokenVersion
    }
    return jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, { expiresIn: "7d" });
}