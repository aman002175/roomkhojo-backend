const mongoose = require('mongoose');

// Logged-in user ke sensitive actions ke liye email OTP:
// - delete-account (current email par OTP)
// - email-change (nayi email par OTP)
const actionOtpSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  purpose: { type: String, enum: ['delete-account', 'email-change'], required: true },
  newEmail: { type: String, lowercase: true, trim: true, default: '' },
  otpHash: { type: String, default: null },
  otpExpires: { type: Date, default: null },
  attempts: { type: Number, default: 0 },
  sendCount: { type: Number, default: 0 },
  sendWindowStart: { type: Date, default: null },
  lastSentAt: { type: Date, default: null }
}, { timestamps: true });

actionOtpSchema.index({ userId: 1, purpose: 1 }, { unique: true });
actionOtpSchema.index({ otpExpires: 1 }, { expireAfterSeconds: 3600 });

module.exports = mongoose.model('ActionOtp', actionOtpSchema);
