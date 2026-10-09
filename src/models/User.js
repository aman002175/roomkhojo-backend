const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },

  // Google users ke liye password optional hai
  password: { type: String },

  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  profilePic: { type: String, default: '' },
  isGoogleUser: { type: Boolean, default: false }, // Pehchanne ke liye

  // JWT invalidation ke liye: password reset/change par bump hota hai,
  // puraane tokens apne aap bekaar ho jaate hain
  tokenVersion: { type: Number, default: 0 }
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
