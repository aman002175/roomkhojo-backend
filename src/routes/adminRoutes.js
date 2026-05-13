const express = require('express');
const router = express.Router();
const Admin = require('../models/Admin');
const mongoose = require('mongoose');

// Default Admin Create Karein (Guaranteed Execution Version)
// Default Admin Create Karein (Force Reset Version)
const seedAdmin = async () => {
  try {
    // 🚨 Purane sabhi aade-tirche admin accounts delete kardo
    await Admin.deleteMany({}); 
    // Ekdum fresh account banao
    await Admin.create({ username: 'admin', password: 'password123' });
    console.log('✅ Admin ID FORCE RESET -> Username: admin | Password: password123');
  } catch (error) {
    console.log('⚠️ Admin Check Failed:', error.message);
  }
};

// 🚨 SMART CHECK: Agar MongoDB pehle hi connect ho chuka hai, toh turant chalao
if (mongoose.connection.readyState === 1) {
  seedAdmin();
} else {
  // Warna connect hone ka wait karo
  mongoose.connection.once('open', seedAdmin);
}

// --- Admin Login API ---
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username, password });
  if (admin) {
    res.json({ success: true, message: 'Login successful' });
  } else {
    res.status(401).json({ success: false, message: 'Username ya Password galat hai!' });
  }
});

// --- Admin Credentials Change API ---
router.post('/change-credentials', async (req, res) => {
  const { oldPassword, newUsername, newPassword } = req.body;
  const admin = await Admin.findOne({ password: oldPassword });
  
  if (!admin) {
    return res.status(401).json({ success: false, message: 'Purana password galat hai!' });
  }

  if (newUsername) admin.username = newUsername;
  if (newPassword) admin.password = newPassword;
  
  await admin.save();
  res.json({ success: true, message: 'Credentials successfully updated!' });
});
const Settings = require('../models/Settings');

// Default Settings Create Karein (Agar pehle se nahi hai)
const seedSettings = async () => {
  try {
    const count = await Settings.countDocuments();
    if (count === 0) await Settings.create({});
  } catch (err) {}
};
if (mongoose.connection.readyState === 1) seedSettings();
else mongoose.connection.once('open', seedSettings);

// --- Get App Settings API ---
router.get('/settings', async (req, res) => {
  const settings = await Settings.findOne({ key: 'app_settings' });
  res.json({ success: true, settings });
});

// --- Update App Settings API ---
router.post('/settings', async (req, res) => {
  const { categories, pricing } = req.body;
  const settings = await Settings.findOneAndUpdate(
    { key: 'app_settings' },
    { categories, pricing },
    { new: true, upsert: true }
  );
  res.json({ success: true, message: 'Settings securely updated!', settings });
});

module.exports = router;
