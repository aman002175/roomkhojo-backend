const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: { 
    folder: 'roomkhojo_ads', // Cloudinary mein is naam ka folder ban jayega
    allowedFormats: ['jpg', 'png', 'jpeg', 'webp'] // Sirf photos allow karega
  },
});

module.exports = multer({ storage: storage });
