import { Request, Response, NextFunction } from "express";


function requireRole(role: string) {
    return (req: Request, res: Response, next: NextFunction) => {
        const authRequest = req as any;
        const authUser = authRequest.user;
        if(!authUser){
            return res.status(401).json({ message: "Unauthorized! You are not authenticated" });
        }
        if(authUser.role !== role){
            return res.status(401).json({ message: "You don't have access to this route" });
        }
        next();
    }
}

export default requireRole;