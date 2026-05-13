const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  
  // 🚨 Yahan se 'required: true' hata diya gaya hai Google Login ke liye
  password: { type: String }, 
  
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  profilePic: { type: String, default: '' },
  isGoogleUser: { type: Boolean, default: false } // Pehchanne ke liye
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);

