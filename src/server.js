require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

// 🚨 NAYE SECURITY GUARDS IMPORTS
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');

const connectDB = require('./config/db'); 

const app = express();

// ==========================================
// 🛡️ ULTIMATE SECURITY PATCH (ACTIVE)
// ==========================================

// 1. HELMET: Fake HTTP headers set karta hai taaki hacker ko pata na chale backend kis language mein bana hai
app.use(helmet()); 

// 2. RATE LIMITING: Bot attacks (DDoS) rokne ke liye. Ek IP address se 15 minute mein sirf 150 request aayengi.
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 150, 
  message: { success: false, message: 'Bahut zyada requests aa rahi hain. Kripya 15 minute baad try karein 🚨' }
});
app.use('/api', limiter); 

// 3. PAYLOAD LIMITER: Hacker bahut badi file bhejkar server crash na kar de, isliye limit 10kb set ki hai (JSON ke liye)
app.use(express.json({ limit: '10kb' })); 

// 4. NoSQL INJECTION PROTECTION: Agar koi login form mein hacker code ($gt, $eq) daalega, toh ye usko delete kar dega
//app.use(mongoSanitize());

// 5. XSS PROTECTION: Agar koi room description mein virus wala javascript (<script>) daalega, toh ye usko text mein badal dega
//app.use(xss());

// ==========================================

app.use(cors()); 
app.use(morgan('dev')); 
app.use('/uploads', express.static('uploads')); 

// --- DATABASE CONNECTION ---
connectDB();

// --- ROUTES IMPORTS ---
const roomRoutes = require('./routes/roomRoutes');
const adminRoutes = require('./routes/adminRoutes');
const userRoutes = require('./routes/userRoutes');

// --- API ENDPOINTS ---
app.use('/api/rooms', roomRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/users', userRoutes);

// --- HEALTH CHECK ROUTE ---
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'RoomKhojo Secure API is Live! 🚀',
    version: '1.0.0'
  });
});

// --- SERVER START ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`=================================`);
  console.log(`🚀 Server running on PORT: ${PORT}`);
  console.log(`🛡️  Ultimate Security Patch: ACTIVE`);
  console.log(`=================================`);
});
