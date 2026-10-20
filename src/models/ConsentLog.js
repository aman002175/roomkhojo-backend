const mongoose = require('mongoose');

// 🧾 Consent ledger — Terms/Privacy acceptance ka proof (email hash form me, plain email nahi).
// Account delete ke baad bhi 180 din tak rakha jata hai (IT Rules 2021 requirement),
// uske baad cleanup cron delete kar deta hai.
const consentLogSchema = new mongoose.Schema({
  emailHash: { type: String, required: true, index: true },
  termsVersion: { type: String, required: true },
  acceptedAt: { type: Date, default: Date.now },
  withdrawnAt: { type: Date, default: null }
}, { timestamps: true });

consentLogSchema.index({ withdrawnAt: 1 });
consentLogSchema.index({ emailHash: 1, acceptedAt: -1 });

module.exports = mongoose.model('ConsentLog', consentLogSchema);
