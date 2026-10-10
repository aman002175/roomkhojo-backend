const mongoose = require('mongoose');

// ❤️ Saved / Wishlist (userId + roomId unique — dobara save nahi hoga)
const favoriteSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  roomId: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true }
}, { timestamps: true });

favoriteSchema.index({ userId: 1, roomId: 1 }, { unique: true });

module.exports = mongoose.model('Favorite', favoriteSchema);
