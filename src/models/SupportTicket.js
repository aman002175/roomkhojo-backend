const mongoose = require('mongoose');

// 🎧 Support tickets — user complaint + photo + admin replies (two-way thread)
const replySchema = new mongoose.Schema({
  by: { type: String, enum: ['user', 'admin'], required: true },
  text: { type: String, required: true, maxlength: 5000 },
  createdAt: { type: Date, default: Date.now }
}, { _id: false });

const ticketSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true, maxlength: 80 },
  userName: { type: String, default: '', maxlength: 80 },
  userEmail: { type: String, default: '', maxlength: 254 },
  contactPhone: { type: String, default: '', maxlength: 15 },
  source: { type: String, enum: ['user', 'auth-help'], default: 'user' },
  category: {
    type: String,
    enum: ['Payment Issue', 'Ad Approval', 'Account & Login', 'Report Fake Ad', 'Other'],
    default: 'Other'
  },
  message: { type: String, required: true, maxlength: 5000 },
  image: { type: String, default: '', maxlength: 500 },
  status: { type: String, enum: ['open', 'replied', 'closed'], default: 'open' },
  replies: { type: [replySchema], default: [] }
}, { timestamps: true });

module.exports = mongoose.model('SupportTicket', ticketSchema);
