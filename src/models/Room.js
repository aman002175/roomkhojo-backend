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
  expiryDate: { type: Date, default: null },

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Room', roomSchema);
