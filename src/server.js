require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');

const connectDB = require('./config/db'); 

const app = express();

// 🚨 EXPRESS 5 QUERY PATCH: Shadows the read-only req.query prototype getter with a writable instance property
// so that legacy middleware (like express-mongo-sanitize) can mutate it safely.
app.use((req, res, next) => {
  if (req.query) {
    Object.defineProperty(req, 'query', {
      value: req.query,
      writable: true,
      configurable: true
    });
  }
  next();
});

// ==========================================
// 🛡️ SECURITY PATCH (ACTIVE)
// ==========================================

// 1. HELMET: HTTP headers secure karta hai
app.use(helmet()); 

// 2. CORS: Sirf allowed frontend se requests accept karega
const allowedOrigins = [
  process.env.FRONTEND_URL,        // .env se aayega (local ya production)
  'http://localhost:5173',          // Vite default port
  'http://localhost:5174',          // Vite alternate port
  'https://roomkhojoo.netlify.app', // User's Netlify Live App
].filter(Boolean); // undefined values hata do

app.use(cors({
  origin: function (origin, callback) {
    // Postman ya server-to-server requests allow karo (origin undefined hoga)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS Error: ${origin} ko allow nahi kiya gaya!`));
    }
  },
  credentials: true, // Cookies/auth headers bhejna ho toh zaroori hai
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-secret'],
}));

// 3. RATE LIMITING: Bot/DDoS attacks rokne ke liye
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 150, 
  message: { success: false, message: 'Bahut zyada requests aa rahi hain. Kripya 15 minute baad try karein 🚨' }
});
app.use('/api', limiter); 

// 4. PAYLOAD LIMITER: Badi files se server crash na ho
app.use(express.json({ limit: '10kb' })); 

// 5. NoSQL INJECTION PROTECTION: MongoDB injection attacks rokta hai
app.use(mongoSanitize());

// 6. XSS PROTECTION: Express 5 safe recursive sanitization (fixes getter-only req.query issues)
const cleanXss = (val) => {
  if (typeof val === 'string') {
    return val.replace(/<script[^>]*>([\s\S]*?)<\/script>/gi, '')
              .replace(/<[^>]*>/g, '');
  }
  if (Array.isArray(val)) {
    return val.map(cleanXss);
  }
  if (val && typeof val === 'object') {
    const cleanObj = {};
    for (const key in val) {
      if (Object.prototype.hasOwnProperty.call(val, key)) {
        cleanObj[key] = cleanXss(val[key]);
      }
    }
    return cleanObj;
  }
  return val;
};

const xssClean = (req, res, next) => {
  if (req.body) req.body = cleanXss(req.body);
  if (req.params) req.params = cleanXss(req.params);
  if (req.query) {
    const cleanedQuery = cleanXss(req.query);
    Object.defineProperty(req, 'query', {
      value: cleanedQuery,
      writable: true,
      configurable: true
    });
  }
  next();
};

app.use(xssClean);

// ==========================================

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

// --- GLOBAL ERROR HANDLER ---
app.use((err, req, res, next) => {
  if (err.message && err.message.startsWith('CORS Error')) {
    return res.status(403).json({ success: false, message: err.message });
  }
  console.error('❌ Server Error:', err.message);
  res.status(500).json({ success: false, message: 'Server mein kuch gadbad hai!' });
});

// --- SERVER START ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`=================================`);
  console.log(`🚀 Server running on PORT: ${PORT}`);
  console.log(`🛡️  Security: ACTIVE`);
  console.log(`🌐 Allowed Origins: ${allowedOrigins.join(', ')}`);
  console.log(`=================================`);
});
