const express = require('express');
const router = express.Router();
const Room = require('../models/Room');
const authMiddleware = require('../middleware/authMiddleware');
const upload = require('../config/cloudinary');

// --- ADMIN ROUTES ---
router.get('/admin/all', authMiddleware, async (req, res) => {
  try {
    const rooms = await Room.find().sort({ createdAt: -1 });
    res.status(200).json({ success: true, rooms });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// --- POST NEW AD ---
router.post('/', upload.single('image'), async (req, res) => {
  try {
    const newRoomData = {
      title: req.body.title, price: req.body.price, type: req.body.type, category: req.body.category,
      landmark: req.body.landmark, mobile: req.body.mobile, description: req.body.description,
      lng: Number(req.body.lng), lat: Number(req.body.lat),
      isPromoted: req.body.isPromoted === 'true', userId: req.body.userId || 'unknown',
      ownerName: req.body.ownerName || 'Owner', promoPlan: req.body.promoPlan || 'regular',
      paymentCode: req.body.paymentCode || 'FREE', 
      image: req.file ? req.file.path : '' 
    };

    const newRoom = new Room(newRoomData);
    const savedRoom = await newRoom.save();
    res.status(201).json({ success: true, message: "Ad submitted!", room: savedRoom });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// --- LIVE ROOMS (MAP VIEW) ---
router.get('/', async (req, res) => {
  try {
    const currentDate = new Date();
    const rooms = await Room.find({ 
      isApproved: true, 
      isActive: true,
      $or: [ { expiryDate: null }, { expiryDate: { $gte: currentDate } } ]
    });
    res.status(200).json({ success: true, count: rooms.length, rooms });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// User Dashboard Ads
router.get('/user/:userId', async (req, res) => {
  try {
    const rooms = await Room.find({ userId: req.params.userId }).sort({ createdAt: -1 });
    res.json({ success: true, rooms });
  } catch (error) { res.status(500).json({ success: false }); }
});

router.patch('/:id/toggle-status', async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    room.isActive = !room.isActive;
    await room.save();
    res.json({ success: true, isActive: room.isActive, message: 'Status Updated' });
  } catch (error) { res.status(500).json({ success: false }); }
});

// 🚨 SMART EDIT ROUTE (Anti-Fraud)
router.put('/:id/edit', upload.single('image'), async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ success: false, message: 'Room not found' });

    // Update details (Location aur dusri details update hogi)
    room.title = req.body.title || room.title;
    room.price = req.body.price || room.price;
    room.type = req.body.type || room.type;
    room.category = req.body.category || room.category;
    room.landmark = req.body.landmark || room.landmark;
    room.mobile = req.body.mobile || room.mobile;
    room.description = req.body.description || room.description;
    
    // User plan/payment nahi badal sakta
    if (req.file) room.image = req.file.path;

    // 🚨 FRAUD PROTECTION: User ne edit kiya = Approve hategi aur Pending me jayega!
    room.isApproved = false; 

    await room.save();
    res.status(200).json({ success: true, message: 'Ad updated! Sent to Admin for verification.', room });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// --- ADMIN APPROVE LOGIC ---
router.patch('/:id/approve', async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    room.isApproved = true;

    // 🚨 TIMER LOCK: Sirf pehli baar approve hone par hi Expiry Date set hogi.
    // Agar Edit hone ke baad wapas Approve ho raha hai, toh puraani date hi rahegi!
    if (room.isPromoted && room.promoPlan !== 'regular' && !room.expiryDate) {
      const days = parseInt(room.promoPlan);
      room.expiryDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    }
    
    await room.save();
    res.status(200).json({ success: true, message: "Room Approved!", room });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

router.delete('/:id', async (req, res) => {
  try {
    await Room.findByIdAndDelete(req.params.id);
    res.status(200).json({ success: true, message: "Room Deleted!" });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

module.exports = router;
