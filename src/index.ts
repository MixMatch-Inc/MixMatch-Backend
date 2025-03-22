import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import logger from './config/logger';
import { loggingHandler } from './middleware/pinoHttp';
import { routeError } from './middleware/routeError';
import authRoutes from './routes/authRoutes';

// Load environment variables before using them
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3100;

// Connect to MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/mixmatch';

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => {
    logger.info('Connected to MongoDB Atlas successfully');
  })
  .catch((err) => {
    logger.error('Error connecting to MongoDB:', err);
    process.exit(1);
  });

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

// Routes
app.use('/health', (req, res) => {
  res.status(200).json({ greeting: 'Hello World! Mixmatch' });
});

// Auth routes
app.use('/api/auth', authRoutes);

app.use(routeError);

app.listen(PORT, () => {
  logger.info(
    `<---------------------------------------------------------------->`
  );
  logger.info(`Server is running on port ${PORT}`);
  logger.info(
    `<---------------------------------------------------------------->`
  );
});
