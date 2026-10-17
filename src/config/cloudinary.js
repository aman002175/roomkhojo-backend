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
  // H3 fix: unlimited upload DoS rokne ke liye — har file max 2MB, max 6 files
  limits: { fileSize: 2 * 1024 * 1024, files: 6 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpe?g|png|webp)$/.test(file.mimetype)) return cb(null, true);
    cb(new Error('Sirf JPG, PNG ya WebP photo allowed hai.'));
  }
});

// Buffer → Cloudinary (secure_url wapas milta hai, DB me wahi save hota hai)
// P1 #23: timeout 60s — Cloudinary hang ho toh request kabhi na latke.
const uploadBufferToCloudinary = (file) => new Promise((resolve, reject) => {
  const uploadStream = cloudinary.uploader.upload_stream(
    { folder: 'roomkhojo_ads', allowed_formats: ['jpg', 'png', 'jpeg', 'webp'], timeout: 60000 },
    (error, result) => (error ? reject(error) : resolve(result))
  );
  Readable.from(file.buffer).pipe(uploadStream);
});

// 🧹 P1 #21: stored secure_url se Cloudinary public_id nikaalo.
// Sirf apne folder ('roomkhojo_ads') ka clean URL parse hota hai; transform wala URL
// ya doosra folder → null (galat asset delete KABHI nahi — fail-closed).
const publicIdFromUrl = (url) => {
  try {
    if (typeof url !== 'string' || !url.includes('/image/upload/')) return null;
    const after = url.split('/image/upload/')[1];
    if (!after) return null;
    const parts = after.split('/').filter(Boolean);
    if (parts[0] && /^v\d+$/.test(parts[0])) parts.shift();
    const filePath = parts.join('/');
    if (!filePath.startsWith('roomkhojo_ads/')) return null;
    return filePath.replace(/\.(jpe?g|png|webp)$/i, '') || null;
  } catch { return null; }
};

// Orphan photos ka best-effort delete — overall max ~9s, kabhi reject nahi karta
// (caller hamesha aage badhta hai; Cloudinary down ho toh sirf skip hota hai).
const destroyByUrls = async (urls) => {
  if (!process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) return;
  const ids = [...new Set((urls || []).map(publicIdFromUrl).filter(Boolean))];
  if (ids.length === 0) return;
  await Promise.race([
    Promise.allSettled(ids.map((id) => cloudinary.uploader.destroy(id, { timeout: 8000 }))),
    new Promise((resolve) => setTimeout(resolve, 9000))
  ]);
};

upload.uploadBufferToCloudinary = uploadBufferToCloudinary;
upload.destroyByUrls = destroyByUrls;

module.exports = upload;
