import { Router } from "express";
import passport from "passport";
import { googleCallback, logoutController } from "../controllers/auth.controller";

const authRoutes = Router();

authRoutes.get(
    "/google",
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })
);

authRoutes.get(
    "/google/callback",
    passport.authenticate("google", {
        failureRedirect: "/",
    }),
    googleCallback
);

authRoutes.get("/logout", logoutController);

export default authRoutes;