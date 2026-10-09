const mongoose = require('mongoose');

// Serverless (Vercel) par har request par naya connection mat banao —
// pehla connection cache karke reuse karo (B3 fix).
let cachedConn = global._mongooseConn || null;

const connectDB = async () => {
  if (cachedConn) {
    return cachedConn;
  }
  try {
    // Ye URI .env file se aayegi
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`=================================`);
    console.log(`☁️  MongoDB Connected: ${conn.connection.host}`);
    console.log(`=================================`);
    cachedConn = conn;
    global._mongooseConn = conn;
    return conn;
  } catch (error) {
    console.error(`❌ Database Error: ${error.message}`);
    // Serverless me process.exit mat karo (request fail hogi, instance nahi marega)
    if (process.env.VERCEL) throw error;
    process.exit(1); // Normal server par fail ho toh rok do
  }
};

module.exports = connectDB;
