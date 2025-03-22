import express from 'express';
import { signup } from '../controllers/authController';

const router = express.Router();

/**
 * @route   POST /auth/signup
 * @desc    Register a new user
 * @access  Public
 */
router.post('/signup', signup);

export default router; 