import { Request, Response } from 'express';
import User, { UserRole } from '../models/User';
import logger from '../config/logger';

/**
 * User signup controller
 * @param req - Express request object
 * @param res - Express response object
 */
export const signup = async (req: Request, res: Response): Promise<void> => {
  try {
    const { fullName, email, password, role, phone, profilePicture } = req.body;

    // Validate required fields
    if (!fullName || !email || !password || !role) {
      res.status(400).json({
        success: false,
        message: 'Missing required fields',
      });
      return;
    }

    // Validate role is one of the allowed values
    if (!Object.values(UserRole).includes(role as UserRole)) {
      res.status(400).json({
        success: false,
        message: `Role must be one of: ${Object.values(UserRole).join(', ')}`,
      });
      return;
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(409).json({
        success: false,
        message: 'User with this email already exists',
      });
      return;
    }

    // Create new user
    const newUser = await User.create({
      fullName,
      email,
      password,
      role,
      phone,
      profilePicture,
      verified: false,
    });

    // Remove password from response using object destructuring
    const userObj = newUser.toObject();
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: _, ...userResponse } = userObj;

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: userResponse,
    });
  } catch (error) {
    logger.error('Error in signup controller:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: (error as Error).message,
    });
  }
}; 