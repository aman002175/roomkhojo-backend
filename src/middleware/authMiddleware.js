module.exports = (req, res, next) => {
  const adminSecret = req.header('x-admin-secret');

  // Secret key ab .env file se aayegi, hardcode nahi hogi
  if (!process.env.ADMIN_SECRET_KEY) {
    console.error('❌ ADMIN_SECRET_KEY .env mein set nahi hai!');
    return res.status(500).json({ success: false, message: 'Server configuration error.' });
  }

  if (adminSecret === process.env.ADMIN_SECRET_KEY) {
    next();
  } else {
    res.status(403).json({ success: false, message: 'Access Denied! Tum admin nahi ho.' });
  }
};
