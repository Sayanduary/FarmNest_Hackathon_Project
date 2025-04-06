import { Router } from 'express';
import { 
  registerUserController, 
  loginController, 
  logoutController, 
  uploadAvatar,
  updateUserDetails,
  verifyEmailController,
  forgotPasswordController,
  verifyForgotPasswordOtp,
  resetPassword,
  refreshTokenController,
  getUserDetails
} from '../controllers/user.controller.js';
import rateLimit from 'express-rate-limit';
import auth from '../middlewares/auth.js';
import { upload, handleMulterErrors } from '../middlewares/multer.js'

const userRouter = Router();

// Rate limiting for security
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per window
  message: {
    message: 'Too many login attempts, please try again after 15 minutes',
    error: true,
    success: false
  }
});

// Rate limiter for password reset attempts
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 reset attempts per hour
  message: {
    message: 'Too many password reset attempts, please try again after an hour',
    error: true,
    success: false
  }
});

// Public routes
userRouter.post('/register', registerUserController);
userRouter.post('/verify-email', verifyEmailController);
userRouter.post('/login', loginLimiter, loginController);
userRouter.post('/forgot-password', passwordResetLimiter, forgotPasswordController);
userRouter.post('/verify-otp', verifyForgotPasswordOtp);
userRouter.post('/reset-password', resetPassword);
userRouter.post('/refresh-token', refreshTokenController);

// Protected routes (require authentication)
userRouter.get('/me', auth, getUserDetails);
userRouter.post('/logout', auth, logoutController);
userRouter.post('/upload-avatar', auth, upload, handleMulterErrors, uploadAvatar);
userRouter.put('/update', auth, updateUserDetails);

// Optional protected route examples (keeping your example route)
userRouter.get('/profile', auth, (req, res) => {
  res.json({
    message: 'Protected route accessed',
    userId: req.userId,
    success: true
  });
});

export default userRouter;