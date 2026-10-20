const express = require('express');
const router = express.Router();
const Room = require('../models/Room');
const ContactReveal = require('../models/ContactReveal');
const SupportTicket = require('../models/SupportTicket');
const ConsentLog = require('../models/ConsentLog');

const RETENTION_DAYS = 180;

// Shared guard: production me CRON_SECRET ke bina kuch na chale.
// Data-delete wale cron me secret hamesha zaroori (accidental wipe se bachne ke liye).
const cronGuard = (req, res, { requireSecret = false } = {}) => {
  const secret = process.env.CRON_SECRET;
  const isProd = process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL);
  if (!secret) {
    if (requireSecret || isProd) {
      console.error('⏰ CRON_SECRET set nahi hai — cron endpoint band hai.');
      res.status(503).json({ success: false, message: 'Cron secret configure nahi hai.' });
      return false;
    }
  } else if (req.headers.authorization !== `Bearer ${secret}`) {
    res.status(401).json({ success: false, message: 'Unauthorized' });
    return false;
  }
  return true;
};

// ⏰ P1 #22: Promo/banner expiry cron (Vercel Cron → roz ek baar).
// Pehle: isPromoted DB me kabhi false nahi hota tha → admin stats galat, papraane par bhi
// "promoted" ginte the. Ab beeti hui expiry roz flip hoti hai (idempotent — dobara chalao
// toh kuch nahi bigadta; naturally expiry wale ads ko hi touch karta hai).
// Protection: CRON_SECRET env set ho toh Vercel ka Authorization header verify hota hai
// (Vercel khud bhejta hai). Bina secret ke bhi endpoint chalta hai — operation harmless hai.
router.get('/expire-promos', async (req, res) => {
  try {
    if (!cronGuard(req, res)) return;
    const now = new Date();
    const promos = await Room.updateMany(
      { isPromoted: true, expiryDate: { $ne: null, $lte: now } },
      { $set: { isPromoted: false, promoPlan: 'regular' } }
    );
    const banners = await Room.updateMany(
      { isBannerActive: true, bannerExpires: { $ne: null, $lte: now } },
      { $set: { isBannerActive: false } }
    );
    console.log(`⏰ expire-promos: promos=${promos.modifiedCount}, banners=${banners.modifiedCount}`);
    res.json({ success: true, expiredPromos: promos.modifiedCount, expiredBanners: banners.modifiedCount });
  } catch (error) {
    console.error('Cron expire-promos error:', error.message);
    res.status(500).json({ success: false, message: 'Cron error' });
  }
});

// 🧹 Data-retention cleanup (Privacy Policy #9 ke mutabik):
// - ContactReveal (number-reveal records) → 180 din baad delete
// - Closed SupportTickets (reports/complaints) → 180 din baad delete
// - Withdrawn ConsentLog (consent proof) → withdrawal ke 180 din baad delete
// Open/replied tickets kabhi auto-delete nahi (investigation pending ho sakti hai).
router.get('/cleanup-retention', async (req, res) => {
  try {
    if (!cronGuard(req, res, { requireSecret: true })) return;
    const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000);
    const [reveals, tickets, consents] = await Promise.all([
      ContactReveal.deleteMany({ createdAt: { $lt: cutoff } }),
      SupportTicket.deleteMany({ status: 'closed', updatedAt: { $lt: cutoff } }),
      ConsentLog.deleteMany({ withdrawnAt: { $ne: null, $lte: cutoff } })
    ]);
    console.log(`🧹 retention: reveals=${reveals.deletedCount}, tickets=${tickets.deletedCount}, consents=${consents.deletedCount}`);
    res.json({
      success: true,
      retentionDays: RETENTION_DAYS,
      deletedReveals: reveals.deletedCount,
      deletedTickets: tickets.deletedCount,
      deletedConsentLogs: consents.deletedCount
    });
  } catch (error) {
    console.error('Cron cleanup-retention error:', error.message);
    res.status(500).json({ success: false, message: 'Cron error' });
  }
});

module.exports = router;
