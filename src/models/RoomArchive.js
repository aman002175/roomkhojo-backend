const mongoose = require('mongoose');

const roomArchiveSchema = new mongoose.Schema({
  originalId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  room: { type: mongoose.Schema.Types.Mixed, required: true },
  deletedBy: { type: String, default: '' },
  deletedByRole: { type: String, enum: ['admin', 'user', 'system'], default: 'system' },
  reason: { type: String, default: '', maxlength: 200 },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

roomArchiveSchema.index({ createdAt: 1 }, { expireAfterSeconds: 180 * 24 * 60 * 60 });

module.exports = mongoose.model('RoomArchive', roomArchiveSchema);
