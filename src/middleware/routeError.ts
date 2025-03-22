import { ErrorRequestHandler } from 'express';
import logger from '../config/logger';

export const routeError: ErrorRequestHandler = (error, req, res, next) => {
  logger.error(error);
  res.status(error.status || 500).json({ error: error.message || 'Internal Server Error' });
};
