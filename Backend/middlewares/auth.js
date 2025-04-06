import jwt from 'jsonwebtoken';

const auth = async (request, response, next) => {
    try {
        // Extract token from either cookies or header
        const token = request.cookies.accessToken ||
            (request.headers.authorization &&
                request.headers.authorization.startsWith('Bearer ') &&
                request.headers.authorization.split(' ')[1]);

        // Check if token exists
        if (!token) {
            return response.status(401).json({
                message: 'Authentication token required',
                error: true,
                success: false
            });
        }

        // Verify token
        let decoded;
        try {
            decoded = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        } catch (err) {
            return response.status(401).json({
                message: 'Invalid or expired token',
                error: true,
                success: false
            });
        }

        // Verify decoded payload has required fields
        if (!decoded.id) {
            return response.status(401).json({
                message: 'Invalid token payload',
                error: true,
                success: false
            });
        }

        // Attach user ID to request
        request.userId = decoded.id;
        next();

    } catch (error) {
        return response.status(500).json({
            message: 'Authentication error',
            error: true,
            success: false,
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

export default auth;