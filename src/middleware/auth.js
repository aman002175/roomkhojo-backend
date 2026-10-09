const jwt = require('jsonwebtoken');
const User = require('../models/User');

const getSecret = () => {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET .env me set nahi hai!');
  }
  return process.env.JWT_SECRET;
};

// Normal user token (7 din) — tokenVersion ke saath taaki
// password reset/change par puraane tokens bekaar ho jayein
const signUser = (user) => jwt.sign(
  {
    id: user._id.toString(),
    email: user.email,
    role: user.role || 'user',
    tv: user.tokenVersion || 0
  },
  getSecret(),
  { expiresIn: '7d' }
);

// Admin token (12 ghante, chhota expiry)
const signAdmin = (admin) => jwt.sign(
  { id: admin._id.toString(), role: 'admin' },
  getSecret(),
  { expiresIn: '12h' }
);

const getBearerToken = (req) => {
  const header = req.header('Authorization') || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
};

// Login zaroori hai — user ya admin dono chalenge
const requireAuth = async (req, res, next) => {
  const token = getBearerToken(req);
  if (!token) {
    return res.status(401).json({ success: false, message: 'Login zaroori hai.' });
  }
  try {
    const decoded = jwt.verify(token, getSecret());
    if (decoded.role === 'admin') {
      req.user = { id: decoded.id, role: 'admin' };
      return next();
    }
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Account nahi mila. Dobara login karein.' });
    }
    if ((user.tokenVersion || 0) !== (decoded.tv || 0)) {
      return res.status(401).json({ success: false, message: 'Session expire ho gaya. Dobara login karein.' });
    }
    req.user = { id: user._id.toString(), email: user.email, role: user.role };
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Session expire ho gaya. Dobara login karein.' });
  }
};

// Sirf admin — role check ke saath
const requireAdmin = (req, res, next) => {
  const token = getBearerToken(req);
  if (!token) {
    return res.status(401).json({ success: false, message: 'Admin login zaroori hai.' });
  }
  try {
    const decoded = jwt.verify(token, getSecret());
    if (decoded.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access Denied! Tum admin nahi ho.' });
    }
    req.user = { id: decoded.id, role: 'admin' };
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Admin session expire. Dobara login karein.' });
  }
};

module.exports = { signUser, signAdmin, requireAuth, requireAdmin };
