const mongoose = require('mongoose');

const settingSchema = new mongoose.Schema({
  categories: { type: Array, default: ['PG', 'Flat', 'Hostel', 'Library', 'Office'] },
  pricing: {
    regular: { type: String, default: '0' },
    promo7: { type: String, default: '299' },
    promo15: { type: String, default: '499' },
    promo30: { type: String, default: '899' },
    
    // 🚨 YE NAYI LINE ADD KARNI HAI YAHAN
    upiId: { type: String, default: '9145891108@ikwik' } 
  }
});

module.exports = mongoose.model('Setting', settingSchema);
