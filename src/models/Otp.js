const mongoose = require('mongoose');

// Password-reset OTP + reset-token store (AUDIT R1-R4)
// OTP kabhi plain me save nahi hota — sirf SHA-256 hash.
const otpSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },

  // Step 1: OTP stage
  otpHash: { type: String, default: null },
  otpExpires: { type: Date, default: null },
  attempts: { type: Number, default: 0 },

  // OTP resend abuse rokne ke liye (max 3 OTP per 15 min)
  sendCount: { type: Number, default: 0 },
  sendWindowStart: { type: Date, default: null },
  lastSentAt: { type: Date, default: null },

  // Step 2: OTP verify ke baad single-use reset token
  resetTokenHash: { type: String, default: null },
  resetExpires: { type: Date, default: null }
}, { timestamps: true });

module.exports = mongoose.model('Otp', otpSchema);
