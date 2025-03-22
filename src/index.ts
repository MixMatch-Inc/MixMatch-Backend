import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import session from "cookie-session"

import './config/passport.config';
import passport from "passport";
import logger from './config/logger';
import { loggingHandler } from './middleware/pinoHttp';
import { routeError } from './middleware/routeError';
import authRoutes from './routes/auth.route';

dotenv.config();
const app = express();

app.use(
  cors({
    origin: '*',
    allowedHeaders: '*',
    exposedHeaders: '*',
  })
);

app.use(loggingHandler);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: 'session',
  keys: [process.env.SESSION_SECRET as string],
  maxAge: 24 * 60 * 60 * 1000,
  secure: process.env.NODE_ENV === "production",
  httpOnly: true,
  sameSite: "lax",
}))
app.use(passport.initialize());
app.use(passport.session());

app.use('/health', (req, res) => {
  res.status(200).json({ greeting: 'Hello World! Mixmatch' });
});

app.use("/api/auth", authRoutes);

app.use(routeError);

app.listen(process.env.PORT, () => {
  logger.info(
    `<---------------------------------------------------------------->`
  );
  logger.info(`Server is running on port ${process.env.PORT}`);
  logger.info(
    `<---------------------------------------------------------------->`
  );
});
