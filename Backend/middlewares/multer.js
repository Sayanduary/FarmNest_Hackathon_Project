import multer from 'multer';

// Configure storage
const storage = multer.memoryStorage();

// File filter for image validation
const fileFilter = (req, file, cb) => {
    // Accept images only
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowedTypes.includes(file.mimetype)) {
        return cb(new Error('Only images (JPEG, PNG, GIF, WEBP) are allowed'), false);
    }
    cb(null, true);
};

// Multer configuration
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
        files: 1, // Max 1 file per request
    },
    fileFilter: fileFilter
}).single('image'); // Expecting a single file with field name 'image'

/**
 * Middleware to handle multer errors
 */
const handleMulterErrors = (err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        // Multer-specific errors
        return res.status(400).json({
            message: err.message,
            error: true,
            success: false
        });
    } else if (err) {
        // Custom errors from fileFilter
        return res.status(400).json({
            message: err.message,
            error: true,
            success: false
        });
    }
    next();
};

export { upload, handleMulterErrors };