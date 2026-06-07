const mongoose = require('mongoose');

const settingSchema = new mongoose.Schema({
  // 👇 BHOOT KO BHAGANE WALI ASLI LINE (Ye sabse zaroori hai!)
  key: { type: String, default: 'app_settings' }, 

  categories: { type: Array, default: ['PG', 'Flat', 'Hostel', 'Library', 'Office'] },
  facilities: { type: Array, default: ['Wi-Fi', 'AC', 'Water 24x7', 'Electricity', 'Geyser', 'RO Water', 'Parking', 'CCTV', 'Meals', 'Attached Washroom'] },
  pricing: {
    regular: { type: String, default: '0' },
    promo7: { type: String, default: '299' },
    promo15: { type: String, default: '499' },
    promo30: { type: String, default: '899' },
    upiId: { type: String, default: '9145891108@ikwik' } 
  }
});

module.exports = mongoose.model('Setting', settingSchema);
