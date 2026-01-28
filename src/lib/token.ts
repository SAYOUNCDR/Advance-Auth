import jwt from "jsonwebtoken";

export function generateAccessToken(userId: string, role: "user" | "admin", tokenVersion: number) {
    const payload = {
        id: userId,
        role,
        tokenVersion
    }
    return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, { expiresIn: "30min" });
}

export function verifyAccessToken(token: string) {
    try {
        return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
            id: string;
            role: "user" | "admin";
            tokenVersion: number;
        };
    } catch (error) {
        return null;
    }
}


export function generateRefreshToken(userId: string, tokenVersion: number) {
    const payload = {
        id: userId,
        tokenVersion
    }
    return jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, { expiresIn: "7d" });
}


export function verifyRefreshToken(token: string) {
    try {
        const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as {
            id: string;
            tokenVersion: number;
        };
        return payload;
    } catch (error) {
        return null;
    }
}