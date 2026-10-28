const mongoose = require('mongoose');

const settingSchema = new mongoose.Schema({
  // 👇 BHOOT KO BHAGANE WALI ASLI LINE (Ye sabse zaroori hai!)
  key: { type: String, default: 'app_settings' }, 

  categories: { type: Array, default: ['PG', 'Flat', 'Room', 'Hostel', 'Library', 'Office'] },
  facilities: { type: Array, default: ['Wi-Fi', 'AC', 'Water 24x7', 'Electricity', 'Geyser', 'RO Water', 'Parking', 'CCTV', 'Meals', 'Attached Washroom'] },
  pricing: {
    regular: { type: String, default: '0' },
    promo7: { type: String, default: '299' },
    promo15: { type: String, default: '499' },
    promo30: { type: String, default: '899' },
    upiId: { type: String, default: '9145891108@ikwik' },
    // 🎯 Banner add-on: kitna charge + kitne din (admin editable)
    bannerPrice: { type: String, default: '499' },
    bannerDays: { type: String, default: '7' },
    // 🧾 Service provider listing: admin-controlled per-day rate (0 = free)
    serviceDailyRate: { type: String, default: '0' }
  },
  // 🟢 Free/regular ads bina admin-approval ke live? (admin toggle)
  // Promo/paid ads HAMESHA approval mangte hain (payment verify).
  autoApproveFree: { type: Boolean, default: false },
  // 📞 P1: 1 user 1 din me kitne owner numbers reveal kar sakta hai (admin editable)
  contactRevealLimit: { type: Number, default: 15 },
  // Admin panel ka secret path — frontend App.jsx backend se fetch karta hai
  adminPath: { type: String, default: '/admin-secret-29' },
  // 🔐 ADMIN_FORCE_RESET one-shot marker — recovery ek hi baar chale (P0 fix).
  // Dobara force-reset chahiye ho toh DB me ye field null kar do.
  forceResetAt: { type: Date, default: null }
});

module.exports = mongoose.model('Setting', settingSchema);
