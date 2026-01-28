import { Request, Response, Router } from "express";
import { User } from "../models/user.model";
import requireRole from "../middleware/requireRole";
import requireAuth from "../middleware/requireAuth";

const router = Router();

router.get("/users", requireAuth, requireRole("admin"), async (req: Request, res: Response) => {
    try {
        const users = await User.find().sort({ createdAt: -1 });
        const response = {
            totalUsers: users.length,
            users: users.map((user) => {
                return {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    isEmailVerified: user.isEmailVerified,
                    twoFactorEnabled: user.twoFactorEnabled,
                    createdAt: user.createdAt.toISOString(),
                    updatedAt: user.updatedAt.toISOString()
                }
            })
        }
        return res.status(200).json(response);
    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error" });
    }
})

export default router;
