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
  // 📸 Photo gallery (max 6) — image = pehli photo (puraane code ke liye)
  images: { type: [String], default: [] },
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

  // 💰 #56: admin approve waqt record hui amount (stats asli revenue dikhaye)
  paymentAmount: { type: Number, default: 0 },
  bannerAmount: { type: Number, default: 0 },
  // 📍 Aas-paas ke landmarks (user-selected): [{name, cat, lat, lng, distM}]
  // Student ko dikhta hai: "Coaching X (350m) • Bus Stand (800m)"
  landmarks: { type: [{ name: String, cat: String, lat: Number, lng: Number, distM: Number }], default: [] },
  // 🎯 BANNER ADD-ON (paid): request + admin activation + expiry
  bannerRequested: { type: Boolean, default: false },
  bannerRef: { type: String, default: '' },
  isBannerActive: { type: Boolean, default: false },
  bannerExpires: { type: Date, default: null },
  // P1-2 fix: report ke liye login zaroori — kis user (sha1 hash) ne report kiya
  // (public API me kabhi nahi jayegi)
  reportedBy: { type: [String], default: [], select: false },
  // 🔗 Purane (orphan) ad claim flow: mobile-match + admin approval (#13 fix)
  claimRequestedBy: { type: String, default: null },   // claimant ka Mongo user id
  claimRequestName: { type: String, default: '' },      // admin ko verify karne ke liye naam
  claimRequestedAt: { type: Date, default: null },
  expiryDate: { type: Date, default: null },
  unavailableReportCount: { type: Number, default: 0 },
  // 👁 Ad kitni baar dekha gaya (D1 — dashboard me owner ko dikhta hai)
  views: { type: Number, default: 0 },
  // 👁 View-dedupe keys (IP+din hash) — public API me kabhi nahi jayengi (P0 fix)
  viewKeys: { type: [String], default: [], select: false },

  createdAt: { type: Date, default: Date.now }
});

// ⚡ P1 #20: Query indexes (Mongoose connect par auto-build — idempotent, Vercel par bhi).
// NOTE: lat/lng alag Number fields hain (GeoJSON nahi) — 2dsphere index ke liye schema
// migration chahiye; isliye filhaal geo index skip (app ke scale par map client-side hai).
roomSchema.index({ isApproved: 1, isActive: 1, createdAt: -1 }); // public /rooms (live map)
roomSchema.index({ userId: 1, createdAt: -1 });                  // dashboard "my rooms"
roomSchema.index({ isPromoted: 1, expiryDate: 1 });              // promo expiry cron (#22)
roomSchema.index({ isBannerActive: 1, bannerExpires: 1 });       // banner strip + cron

module.exports = mongoose.model('Room', roomSchema);
