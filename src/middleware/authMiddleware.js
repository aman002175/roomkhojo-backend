module.exports = (req, res, next) => {
  // Admin Panel se aane wala header check karenge
  const adminSecret = req.header('x-admin-secret');

  // Aap yahan koi bhi secret key set kar sakte hain, abhi ke liye "my-secret-key" rakhte hain
  if (adminSecret === 'my-secret-key') {
    next(); // Sab sahi hai, aage badho
  } else {
    res.status(403).json({ success: false, message: 'Access Denied! Tum admin nahi ho.' });
  }
};
