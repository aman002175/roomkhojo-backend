const mongoose = require('mongoose');

// 📞 P1: Number-reveal ledger — kaun user, kis din, kaunsa number dekh chuka hai.
// (userId+roomId+date unique) → ek hi ad ka number baar-baar kholne par limit nahi lagti,
// par naye ads ke numbers par daily limit chalti hai.
const contactRevealSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  roomId: { type: String, required: true },
  date: { type: String, required: true }, // IST din 'YYYY-MM-DD' (server UTC, user India)
}, { timestamps: true });

contactRevealSchema.index({ userId: 1, roomId: 1, date: 1 }, { unique: true });
contactRevealSchema.index({ userId: 1, date: 1 });

module.exports = mongoose.model('ContactReveal', contactRevealSchema);
