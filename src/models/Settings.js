const mongoose = require('mongoose');

const settingSchema = new mongoose.Schema({
  // 👇 BHOOT KO BHAGANE WALI ASLI LINE (Ye sabse zaroori hai!)
  key: { type: String, default: 'app_settings' }, 

  categories: { type: Array, default: ['PG', 'Flat', 'Hostel', 'Library', 'Office'] },
  pricing: {
    regular: { type: String, default: '0' },
    promo7: { type: String, default: '299' },
    promo15: { type: String, default: '499' },
    promo30: { type: String, default: '899' },
    
    // 👇 Aapki add ki hui UPI wali line (Ye ekdum sahi hai)
    upiId: { type: String, default: '9145891108@ikwik' } 
  }
});

module.exports = mongoose.model('Setting', settingSchema);
