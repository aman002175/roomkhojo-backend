const mongoose = require('mongoose');

// 🎧 Support tickets — user complaint + photo + admin replies (two-way thread)
const replySchema = new mongoose.Schema({
  by: { type: String, enum: ['user', 'admin'], required: true },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}, { _id: false });

const ticketSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  userName: { type: String, default: '' },
  userEmail: { type: String, default: '' },
  category: {
    type: String,
    enum: ['Payment Issue', 'Ad Approval', 'Account & Login', 'Report Fake Ad', 'Other'],
    default: 'Other'
  },
  message: { type: String, required: true },
  image: { type: String, default: '' },
  status: { type: String, enum: ['open', 'replied', 'closed'], default: 'open' },
  replies: { type: [replySchema], default: [] }
}, { timestamps: true });

module.exports = mongoose.model('SupportTicket', ticketSchema);
