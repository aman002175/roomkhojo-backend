const express = require('express');
const router = express.Router();
const SupportTicket = require('../models/SupportTicket');
const upload = require('../config/cloudinary');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const CATEGORIES = ['Payment Issue', 'Ad Approval', 'Account & Login', 'Report Fake Ad', 'Other'];

const serverError = (res, err, label) => {
  console.error(`${label}:`, err.message);
  res.status(500).json({ success: false, message: 'Server me gadbad hai. Baad me try karein.' });
};

// --- USER: naya ticket (login zaroori, photo optional) ---
router.post('/', requireAuth, upload.single('images'), async (req, res) => {
  try {
    const { category, message } = req.body || {};
    if (!CATEGORIES.includes(category)) {
      return res.status(400).json({ success: false, message: 'Sahi category chuno.' });
    }
    const cleanMsg = String(message || '').trim().slice(0, 2000);
    if (cleanMsg.length < 5) {
      return res.status(400).json({ success: false, message: 'Apni dikkat thode detail me likho (min 5 letters).' });
    }
    let imageUrl = '';
    if (req.file) {
      try {
        const uploaded = await upload.uploadBufferToCloudinary(req.file);
        imageUrl = uploaded.secure_url || '';
      } catch (uploadErr) {
        // Photo fail ho toh bhi complaint REGISTER hogi (bina photo) — kabhi 500 nahi
        console.error('Ticket-photo upload failed (ticket bina photo save hoga):', uploadErr.message);
      }
    }
    const ticket = await SupportTicket.create({
      userId: req.user.id,
      userName: req.user.role === 'admin' ? 'Admin' : '',
      userEmail: req.user.email || '',
      category,
      message: cleanMsg,
      image: imageUrl
    });
    res.status(201).json({ success: true, message: 'Complaint mil gayi! Admin jald reply karega.', ticket });
  } catch (error) { serverError(res, error, 'Ticket-create error'); }
});

// --- USER: apne tickets (replies ke saath) ---
router.get('/mine', requireAuth, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user.id }).sort({ updatedAt: -1 });
    res.json({ success: true, tickets });
  } catch (error) { serverError(res, error, 'My-tickets error'); }
});

// --- USER: apne ticket par jawab do (two-way thread) ---
router.post('/:id/reply', requireAuth, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ success: false, message: 'Ticket nahi mila.' });
    if (req.user.role !== 'admin' && ticket.userId !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Access Denied!' });
    }
    if (ticket.status === 'closed') {
      return res.status(400).json({ success: false, message: 'Ye ticket closed hai.' });
    }
    const text = String((req.body || {}).text || '').trim().slice(0, 2000);
    if (text.length < 1) {
      return res.status(400).json({ success: false, message: 'Jawab khaali nahi ho sakta.' });
    }
    ticket.replies.push({ by: req.user.role === 'admin' ? 'admin' : 'user', text });
    if (req.user.role !== 'admin') ticket.status = 'open'; // user ne likha = phir se khula
    await ticket.save();
    res.json({ success: true, message: 'Jawab bhej diya.', ticket });
  } catch (error) { serverError(res, error, 'Reply error'); }
});

// --- ADMIN: saare tickets ---
router.get('/admin/all', requireAdmin, async (req, res) => {
  try {
    const tickets = await SupportTicket.find().sort({ updatedAt: -1 });
    const openCount = await SupportTicket.countDocuments({ status: 'open' });
    res.json({ success: true, openCount, tickets });
  } catch (error) { serverError(res, error, 'Admin-tickets error'); }
});

// --- ADMIN: status badlo (open/closed) ---
router.patch('/admin/:id/status', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body || {};
    if (!['open', 'closed'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Status open ya closed ho.' });
    }
    const ticket = await SupportTicket.findByIdAndUpdate(
      req.params.id, { status }, { new: true }
    );
    if (!ticket) return res.status(404).json({ success: false, message: 'Ticket nahi mila.' });
    res.json({ success: true, message: `Ticket ${status} kar diya.`, ticket });
  } catch (error) { serverError(res, error, 'Ticket-status error'); }
});

module.exports = router;
