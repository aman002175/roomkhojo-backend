const mongoose = require('mongoose');

const roomSchema = new mongoose.Schema({
  title: { type: String, required: true },
  price: { type: String, required: true },
  type: { type: String, required: true }, 
  category: { type: String, required: true }, 
  landmark: { type: String }, 
  mobile: { type: String },      
  description: { type: String }, 
  image: { type: String },       
  lng: { type: Number, required: true },
  lat: { type: Number, required: true },
  
  isPromoted: { type: Boolean, default: false }, 
  isApproved: { type: Boolean, default: false }, 
  isActive: { type: Boolean, default: true },    
  
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  userId: { type: String, default: 'unknown' },
  ownerName: { type: String, default: 'Owner' }, 
  promoPlan: { type: String, default: 'regular' }, 
  
  // 🚨 2 NAYE FIELDS: Payment Track aur Expiry ke liye
  paymentCode: { type: String, default: 'FREE' },
  // User ne kaunsa promo plan MAANGA hai ('regular' | '7' | '15' | '30').
  // isPromoted sirf admin approve ke baad true hota hai (C6 fix).
  promoRequested: { type: String, default: 'regular' },
  // User ka UPI Ref/UTR number (admin payment verify karne ke liye dekhta hai)
  paymentRef: { type: String, default: '' },
  // 📍 Aas-paas ke landmarks (user-selected): [{name, cat, lat, lng, distM}]
  // Student ko dikhta hai: "Coaching X (350m) • Bus Stand (800m)"
  landmarks: { type: [{ name: String, cat: String, lat: Number, lng: Number, distM: Number }], default: [] },
  // 🎯 BANNER ADD-ON (paid): request + admin activation + expiry
  bannerRequested: { type: Boolean, default: false },
  bannerRef: { type: String, default: '' },
  isBannerActive: { type: Boolean, default: false },
  bannerExpires: { type: Date, default: null },
  // Report-spam rokne ke liye: kaunsi IPs report kar chuki hain
  reportedIPs: { type: [String], default: [] },
  expiryDate: { type: Date, default: null },
  unavailableReportCount: { type: Number, default: 0 },

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Room', roomSchema);
