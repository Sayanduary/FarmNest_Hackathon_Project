import { v2 as cloudinary } from 'cloudinary';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config({ path: './.env' });

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

/**
 * Uploads an image to Cloudinary
 * @param {Object|Buffer} image - Image object with buffer or raw Buffer
 * @param {string} [folder="farmnest"] - Cloudinary folder name
 * @returns {Promise<Object>} Cloudinary upload result
 * @throws {Error} If upload fails or configuration is invalid
 */
const uploadImageToCloudinary = async (image, folder = "farmnest") => {
    try {
        // Validate input
        if (!image) {
            throw new Error('No image provided');
        }

        // Handle different input types
        let buffer;
        if (Buffer.isBuffer(image)) {
            buffer = image;
        } else if (image.buffer) {
            buffer = image.buffer;
        } else if (typeof image.arrayBuffer === 'function') {
            buffer = Buffer.from(await image.arrayBuffer());
        } else {
            throw new Error('Invalid image format');
        }

        // Validate Cloudinary configuration
        if (!process.env.CLOUDINARY_CLOUD_NAME || 
            !process.env.CLOUDINARY_API_KEY || 
            !process.env.CLOUDINARY_API_SECRET) {
            throw new Error('Cloudinary configuration missing');
        }

        // Upload to Cloudinary
        const uploadResult = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
                {
                    folder,
                    resource_type: 'image',
                    // Optional optimization settings
                    transformation: [
                        { quality: 'auto' },
                        { fetch_format: 'auto' }
                    ]
                },
                (error, result) => {
                    if (error) {
                        reject(error);
                    } else {
                        resolve(result);
                    }
                }
            );
            uploadStream.end(buffer);
        });

        return {
            url: uploadResult.secure_url,
            public_id: uploadResult.public_id,
            asset_id: uploadResult.asset_id,
            bytes: uploadResult.bytes
        };
    } catch (error) {
        throw new Error(`Image upload failed: ${error.message}`);
    }
};

export default uploadImageToCloudinary;