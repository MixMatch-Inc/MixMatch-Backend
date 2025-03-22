import { NextFunction, Request, Response } from "express";
import { asyncHandler } from "../middleware/asyncHandler";

export const googleCallback = asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
        const currentUser = req.user;
        if (!currentUser) {
            return res.redirect(`${process.env.FRONTEND_GOOGLE_CALLBACK_URL}/?status=failure`);
        }
        // redirect to frontend with user data
       return res.redirect("/");
    }
)

export const logoutController = asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
        req.logout((error) => {
            if (error) {
                return next(error);
            }
        });
        req.session = null;
        return res.status(200).json({ message: "Logout successful" });
    }
)