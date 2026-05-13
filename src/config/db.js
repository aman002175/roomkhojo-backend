const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    // Ye URI .env file se aayegi
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`=================================`);
    console.log(`☁️  MongoDB Connected: ${conn.connection.host}`);
    console.log(`=================================`);
  } catch (error) {
    console.error(`❌ Database Error: ${error.message}`);
    process.exit(1); // Agar fail ho jaye toh server rok do
  }
};

module.exports = connectDB;
