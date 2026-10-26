const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  // Verified mobile (signup/ profile) — listing form me prefill hota hai
  phone: { type: String, trim: true, default: '' },

  // Google users ke liye password optional hai
  password: { type: String },

  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  // Admin moderation: suspended/banned users login aur token access dono se blocked
  status: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  statusReason: { type: String, default: '' },
  statusChangedAt: { type: Date, default: null },
  profilePic: { type: String, default: '' },
  isGoogleUser: { type: Boolean, default: false }, // Pehchanne ke liye

  // JWT invalidation ke liye: password reset/change par bump hota hai,
  // puraane tokens apne aap bekaar ho jaate hain
  tokenVersion: { type: Number, default: 0 },
  // Terms & Refund Policy accept karne ka time + kaunsa version accept hua (auth screen checkbox se)
  termsAcceptedAt: { type: Date, default: null },
  termsVersion: { type: String, default: '' }
}, { timestamps: true });

// Password save hone se pehle hash hoga — plain password kabhi DB me nahi jayega
userSchema.pre('save', async function () {
  if (!this.isModified('password') || !this.password) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = function (plainPassword) {
  if (!this.password) return false;
  return bcrypt.compare(plainPassword || '', this.password);
};

module.exports = mongoose.model('User', userSchema);
