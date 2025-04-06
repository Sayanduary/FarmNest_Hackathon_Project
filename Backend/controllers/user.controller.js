import sendEmail from '../config/sendEmail.js'
import UserModel from '../models/user.model.js'
import bcryptjs from 'bcryptjs'
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js'
import forgotPasswordTemplate from '../utils/forgotPasswordTemplate.js'
import generatedOtp from '../utils/generatedOtp.js'
import uploadImageToCloudinary from '../utils/uploadImageClodinary.js'
import jwt from 'jsonwebtoken'

// Standardized response function
const sendResponse = (res, status, message, error, success, data = null) => {
  const response = { message, error, success };
  if (data) response.data = data;
  return res.status(status).json(response);
};

// JWT token generation functions
const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { id: userId },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { id: userId },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
};

export async function registerUserController(request, response) {
  try {
    const { name, email, password } = request.body;

    // Validate required fields
    if (!name || !email || !password) {
      return sendResponse(response, 400, "Please provide name, email, and password", true, false);
    }

    // Check for existing user
    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return sendResponse(response, 409, "Email already registered", true, false);
    }

    // Hash password and create user
    const salt = await bcryptjs.genSalt(10);
    const hashPassword = await bcryptjs.hash(password, salt);

    const newUser = new UserModel({
      name,
      email,
      password: hashPassword,
      verify_email: true // Auto-verified
    });

    const savedUser = await newUser.save();

    // Remove password from response
    const userData = savedUser.toObject();
    delete userData.password;

    return sendResponse(response, 201, "User registered successfully", false, true, userData);
  } catch (error) {
    console.error("Registration error:", error);
    return sendResponse(response, 500, error.message || "Registration failed", true, false);
  }
}

export async function verifyEmailController(request, response) {
  try {
    const { code } = request.body;

    if (!code) {
      return sendResponse(response, 400, "Verification code is required", true, false);
    }

    const user = await UserModel.findById(code);
    if (!user) {
      return sendResponse(response, 400, "Invalid verification code", true, false);
    }

    await UserModel.findByIdAndUpdate(code, { verify_email: true });

    return sendResponse(response, 200, "Email verified successfully", false, true);
  } catch (error) {
    console.error("Email verification error:", error);
    return sendResponse(response, 500, error.message || "Verification failed", true, false);
  }
}

export async function loginController(request, response) {
  try {
    const { email, password } = request.body;

    // Validate required fields
    if (!email || !password) {
      return sendResponse(response, 400, "Email and password are required", true, false);
    }

    // Find user
    const user = await UserModel.findOne({ email });
    if (!user) {
      return sendResponse(response, 404, "User not registered", true, false);
    }

    // Check user status
    if (user.status !== "Active") {
      return sendResponse(response, 403, "Account inactive. Contact admin", true, false);
    }

    // Verify password
    const isPasswordValid = await bcryptjs.compare(password, user.password);
    if (!isPasswordValid) {
      return sendResponse(response, 401, "Invalid password", true, false);
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user._id);

    // Update user with refresh token and last login
    await UserModel.findByIdAndUpdate(user._id, {
      refresh_token: refreshToken,
      last_login_date: new Date()
    });

    // Set cookies
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
    };

    response.cookie('accessToken', accessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000 // 15 minutes
    });

    response.cookie('refreshToken', refreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Send response with user data
    const userData = {
      id: user._id,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      role: user.role
    };

    return sendResponse(response, 200, "Login successful", false, true, {
      user: userData,
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error("Login error:", error);
    return sendResponse(response, 500, error.message || "Login failed", true, false);
  }
}

export async function logoutController(request, response) {
  try {
    const userId = request.userId; // From auth middleware

    if (!userId) {
      return sendResponse(response, 401, "Authentication required", true, false);
    }

    // Clear cookies
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax'
    };

    response.clearCookie("accessToken", cookieOptions);
    response.clearCookie("refreshToken", cookieOptions);

    // Clear refresh token in database
    await UserModel.findByIdAndUpdate(userId, { refresh_token: "" });

    return sendResponse(response, 200, "Logout successful", false, true);
  } catch (error) {
    console.error("Logout error:", error);
    return sendResponse(response, 500, error.message || "Logout failed", true, false);
  }
}

export async function uploadAvatar(request, response) {
  try {
    const userId = request.userId; // From auth middleware
    const image = request.file; // From multer middleware

    if (!userId) {
      return sendResponse(response, 401, "Authentication required", true, false);
    }

    if (!image) {
      return sendResponse(response, 400, "Image file is required", true, false);
    }

    // Upload image to Cloudinary
    const uploadResult = await uploadImageToCloudinary(image);
    if (!uploadResult || !uploadResult.url) {
      return sendResponse(response, 500, "Image upload failed", true, false);
    }

    // Update user avatar
    await UserModel.findByIdAndUpdate(userId, { avatar: uploadResult.url });

    return sendResponse(response, 200, "Profile picture updated successfully", false, true, {
      _id: userId,
      avatar: uploadResult.url
    });
  } catch (error) {
    console.error("Avatar upload error:", error);
    return sendResponse(response, 500, error.message || "Avatar upload failed", true, false);
  }
}

export async function updateUserDetails(request, response) {
  try {
    const userId = request.userId; // From auth middleware
    const { name, email, mobile, password } = request.body;

    if (!userId) {
      return sendResponse(response, 401, "Authentication required", true, false);
    }

    // Check if no fields to update
    if (!name && !email && !mobile && !password) {
      return sendResponse(response, 400, "No fields to update", true, false);
    }

    // Create update object
    const updateData = {};
    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (mobile) updateData.mobile = mobile;

    // Handle password update separately
    if (password) {
      const salt = await bcryptjs.genSalt(10);
      updateData.password = await bcryptjs.hash(password, salt);
    }

    // Update user and return updated document
    const updatedUser = await UserModel.findByIdAndUpdate(
      userId,
      updateData,
      { new: true }
    ).select('-password -refresh_token');

    if (!updatedUser) {
      return sendResponse(response, 404, "User not found", true, false);
    }

    return sendResponse(response, 200, "Profile updated successfully", false, true, updatedUser);
  } catch (error) {
    console.error("Profile update error:", error);
    return sendResponse(response, 500, error.message || "Profile update failed", true, false);
  }
}

export async function forgotPasswordController(request, response) {
  try {
    const { email } = request.body;

    if (!email) {
      return sendResponse(response, 400, "Email is required", true, false);
    }

    const user = await UserModel.findOne({ email });
    if (!user) {
      return sendResponse(response, 404, "Email not registered", true, false);
    }

    // Generate OTP and set expiry
    const otp = generatedOtp();
    const expiryTime = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now

    // Update user with OTP and expiry
    await UserModel.findByIdAndUpdate(user._id, {
      forgot_password_otp: otp,
      forgot_password_expiry: expiryTime
    });

    // Send email with OTP
    await sendEmail({
      sendTo: email,
      subject: "Password Reset OTP - FarmNest",
      html: forgotPasswordTemplate({
        name: user.name,
        otp: otp
      })
    });

    return sendResponse(response, 200, "OTP sent to your email", false, true);
  } catch (error) {
    console.error("Forgot password error:", error);
    return sendResponse(response, 500, error.message || "Failed to send OTP", true, false);
  }
}

export async function verifyForgotPasswordOtp(request, response) {
  try {
    const { email, otp } = request.body;

    if (!email || !otp) {
      return sendResponse(response, 400, "Email and OTP are required", true, false);
    }

    const user = await UserModel.findOne({ email });
    if (!user) {
      return sendResponse(response, 404, "Email not registered", true, false);
    }

    // Check if OTP is expired
    const currentTime = new Date();
    if (!user.forgot_password_expiry || new Date(user.forgot_password_expiry) < currentTime) {
      return sendResponse(response, 400, "OTP has expired", true, false);
    }

    // Verify OTP
    if (otp !== user.forgot_password_otp) {
      return sendResponse(response, 400, "Invalid OTP", true, false);
    }

    // Clear OTP after verification (but don't reset password yet)
    await UserModel.findByIdAndUpdate(user._id, {
      forgot_password_otp: "",
      forgot_password_expiry: null
    });

    return sendResponse(response, 200, "OTP verified successfully", false, true);
  } catch (error) {
    console.error("OTP verification error:", error);
    return sendResponse(response, 500, error.message || "OTP verification failed", true, false);
  }
}

export async function resetPassword(request, response) {
  try {
    const { email, newPassword, confirmPassword } = request.body;

    if (!email || !newPassword || !confirmPassword) {
      return sendResponse(response, 400, "Email, new password, and confirm password are required", true, false);
    }

    if (newPassword !== confirmPassword) {
      return sendResponse(response, 400, "New password and confirm password must match", true, false);
    }

    const user = await UserModel.findOne({ email });
    if (!user) {
      return sendResponse(response, 404, "Email not registered", true, false);
    }

    // Hash and update password
    const salt = await bcryptjs.genSalt(10);
    const hashPassword = await bcryptjs.hash(newPassword, salt);

    await UserModel.findByIdAndUpdate(user._id, {
      password: hashPassword
    });

    return sendResponse(response, 200, "Password updated successfully", false, true);
  } catch (error) {
    console.error("Password reset error:", error);
    return sendResponse(response, 500, error.message || "Password reset failed", true, false);
  }
}

export async function refreshTokenController(request, response) {
  try {
    // Get refresh token from cookie or Authorization header
    const refreshToken = request.cookies.refreshToken ||
      (request.headers.authorization?.startsWith('Bearer ') ?
        request.headers.authorization.split(' ')[1] : null);

    if (!refreshToken) {
      return sendResponse(response, 401, "Refresh token required", true, false);
    }

    // Verify refresh token
    let decodedToken;
    try {
      decodedToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
      return sendResponse(response, 401, "Invalid or expired refresh token", true, false);
    }

    // Get user ID from token
    const userId = decodedToken.id;
    if (!userId) {
      return sendResponse(response, 401, "Invalid token format", true, false);
    }

    // Verify user exists and token matches stored token
    const user = await UserModel.findById(userId);
    if (!user || user.refresh_token !== refreshToken) {
      return sendResponse(response, 401, "Invalid refresh token", true, false);
    }

    // Generate new access token
    const accessToken = jwt.sign(
      { id: userId },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '15m' }
    );

    // Set new access token cookie
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 15 * 60 * 1000 // 15 minutes
    };

    response.cookie('accessToken', accessToken, cookieOptions);

    return sendResponse(response, 200, "Access token refreshed", false, true, {
      accessToken
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    return sendResponse(response, 500, error.message || "Token refresh failed", true, false);
  }
}

export async function getUserDetails(request, response) {
  try {
    const userId = request.userId; // From auth middleware

    if (!userId) {
      return sendResponse(response, 401, "Authentication required", true, false);
    }

    const user = await UserModel.findById(userId)
      .select('-password -refresh_token -forgot_password_otp -forgot_password_expiry');

    if (!user) {
      return sendResponse(response, 404, "User not found", true, false);
    }

    return sendResponse(response, 200, "User details retrieved successfully", false, true, user);
  } catch (error) {
    console.error("Get user details error:", error);
    return sendResponse(response, 500, error.message || "Failed to retrieve user details", true, false);
  }
}