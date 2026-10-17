const express = require('express');
const router = express.Router();
const Room = require('../models/Room');

// ⏰ P1 #22: Promo/banner expiry cron (Vercel Cron → roz ek baar).
// Pehle: isPromoted DB me kabhi false nahi hota tha → admin stats galat, papraane par bhi
// "promoted" ginte the. Ab beeti hui expiry roz flip hoti hai (idempotent — dobara chalao
// toh kuch nahi bigadta; naturally expiry wale ads ko hi touch karta hai).
// Protection: CRON_SECRET env set ho toh Vercel ka Authorization header verify hota hai
// (Vercel khud bhejta hai). Bina secret ke bhi endpoint chalta hai — operation harmless hai.
router.get('/expire-promos', async (req, res) => {
  try {
    const secret = process.env.CRON_SECRET;
    const isProd = process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL);
    // P2-6 fix: production me bina secret ke cron public bilkul na chale
    if (!secret) {
      if (isProd) {
        console.error('⏰ CRON_SECRET set nahi hai — cron endpoint production me band hai.');
        return res.status(503).json({ success: false, message: 'Cron secret configure nahi hai.' });
      }
    } else if (req.headers.authorization !== `Bearer ${secret}`) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
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

module.exports = router;
