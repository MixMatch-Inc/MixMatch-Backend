import passport from "passport";
import { Request } from "express";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

passport.use(
    new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID as string,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
        callbackURL: process.env.GOOGLE_CALLBACK_URL as string,
        scope: ["profile", "email"],
        passReqToCallback: true,
    }, async (req: Request, accessToken, refreshToken, profile, done) => {
        try {
            done(null, profile);
        } catch (error) {
            done(error, false);
        }
    })
)

passport.serializeUser((user: any, done) => done(null, user));
passport.deserializeUser((user: any, done) => done(null, user));