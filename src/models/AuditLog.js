const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  actorId: { type: String, default: '' },
  actorRole: { type: String, enum: ['admin', 'user', 'system'], default: 'system' },
  action: { type: String, required: true, maxlength: 80 },
  targetType: { type: String, default: '', maxlength: 40 },
  targetId: { type: String, default: '', maxlength: 80 },
  ipHash: { type: String, default: '', maxlength: 64 },
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
