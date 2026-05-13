const express = require('express');
const router = express.Router();
const User = require('../models/User');

// 1. Email & Password Signup
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check agar user pehle se hai
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ success: false, message: 'Ye Email pehle se registered hai!' });

    const newUser = await User.create({ name, email, password });
    res.status(201).json({ success: true, message: 'Account ban gaya!', user: { id: newUser._id, name, email } });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 2. Email & Password Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password });
    
    if (!user) return res.status(401).json({ success: false, message: 'Email ya Password galat hai!' });
    res.json({ success: true, message: `Welcome ${user.name}!`, user: { id: user._id, name: user.name, email } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server Error' });
  }
});

// 3. Google Login API
router.post('/google-login', async (req, res) => {
  try {
    const { name, email, picture } = req.body;
    
    let user = await User.findOne({ email });
    
    // Agar Google user pehli baar aaya hai toh database mein account bana do
    if (!user) {
      user = await User.create({ name, email, profilePic: picture, isGoogleUser: true });
    }
    
    res.json({ success: true, message: `Google Login Successful!`, user: { id: user._id, name: user.name, email: user.email, pic: user.profilePic } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Google Login Backend Error' });
  }
});
// GET Total Users Count (Admin Analytics ke liye)
router.get('/count', async (req, res) => {
  try {
    const count = await User.countDocuments();
    res.json({ success: true, count });
  } catch (error) { res.status(500).json({ success: false }); }
});

module.exports = router;
