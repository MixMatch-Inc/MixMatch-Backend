import { NextFunction, Request, Response } from "express";

const isAuthenticated = (req: Request, res: Response, next: NextFunction) => {
    if(!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }
}

export default isAuthenticated;