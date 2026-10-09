const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { Readable } = require('stream');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Memory storage — file RAM me aati hai, seedha Cloudinary jaati hai.
// (multer-storage-cloudinary hata diya: wo cloudinary-v1 par atka tha — H2 fix)
const upload = multer({
  storage: multer.memoryStorage(),
  // H3 fix: unlimited upload DoS rokne ke liye — max 2MB, sirf 1 file
  limits: { fileSize: 2 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpe?g|png|webp)$/.test(file.mimetype)) return cb(null, true);
    cb(new Error('Sirf JPG, PNG ya WebP photo allowed hai.'));
  }
});

// Buffer → Cloudinary (secure_url wapas milta hai, DB me wahi save hota hai)
const uploadBufferToCloudinary = (file) => new Promise((resolve, reject) => {
  const uploadStream = cloudinary.uploader.upload_stream(
    { folder: 'roomkhojo_ads', allowed_formats: ['jpg', 'png', 'jpeg', 'webp'] },
    (error, result) => (error ? reject(error) : resolve(result))
  );
  Readable.from(file.buffer).pipe(uploadStream);
});

upload.uploadBufferToCloudinary = uploadBufferToCloudinary;

module.exports = upload;
