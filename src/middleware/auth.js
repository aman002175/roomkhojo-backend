const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Admin = require('../models/Admin');

const ISSUER = 'roomkhojo';
const USER_AUDIENCE = 'roomkhojo-user';
const ADMIN_AUDIENCE = 'roomkhojo-admin';

const getSecret = () => {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET .env me set nahi hai!');
  }
  return process.env.JWT_SECRET;
};

const verifyToken = (token, audience) => jwt.verify(token, getSecret(), {
  algorithms: ['HS256'],
  issuer: ISSUER,
  audience
});

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
  { algorithm: 'HS256', expiresIn: '7d', issuer: ISSUER, audience: USER_AUDIENCE }
);

// Admin token (12 ghante, chhota expiry) — DB tokenVersion se revoke ho sakta hai
const signAdmin = (admin) => jwt.sign(
  { id: admin._id.toString(), role: 'admin', tv: admin.tokenVersion || 0 },
  getSecret(),
  { algorithm: 'HS256', expiresIn: '12h', issuer: ISSUER, audience: ADMIN_AUDIENCE }
);

const getBearerToken = (req) => {
  const header = req.header('Authorization') || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
};

const expired = (res) => res.status(401).json({ success: false, message: 'Session expire ho gaya. Dobara login karein.' });

const loadAdmin = async (decoded) => {
  if (decoded.role !== 'admin') return null;
  const admin = await Admin.findById(decoded.id).select('_id username tokenVersion');
  if (!admin) return null;
  if ((admin.tokenVersion || 0) !== (decoded.tv || 0)) return null;
  return admin;
};

// Login zaroori hai — user ya admin dono chalenge
const requireAuth = async (req, res, next) => {
  const token = getBearerToken(req);
  if (!token) {
    return res.status(401).json({ success: false, message: 'Login zaroori hai.' });
  }
  try {
    let decoded;
    try {
      decoded = verifyToken(token, USER_AUDIENCE);
    } catch {
      decoded = verifyToken(token, ADMIN_AUDIENCE);
    }
    if (decoded.role === 'admin') {
      const admin = await loadAdmin(decoded);
      if (!admin) return expired(res);
      req.user = { id: admin._id.toString(), role: 'admin' };
      return next();
    }
    if (!decoded.id || !/^[a-f0-9]{24}$/i.test(String(decoded.id))) return expired(res);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Account nahi mila. Dobara login karein.' });
    }
    if ((user.tokenVersion || 0) !== (decoded.tv || 0)) return expired(res);
    if (user.status === 'suspended' || user.status === 'banned') {
      const msg = user.status === 'banned'
        ? 'Account permanently ban hai. Support se sampark karein.'
        : 'Account suspend hai. Support se sampark karein.';
      return res.status(403).json({ success: false, message: msg });
    }
    req.user = { id: user._id.toString(), email: user.email, role: user.role };
    next();
  } catch (err) {
    return expired(res);
  }
};

// Sirf admin — DB-backed session check (password change par purane tokens dead)
const requireAdmin = async (req, res, next) => {
  const token = getBearerToken(req);
  if (!token) {
    return res.status(401).json({ success: false, message: 'Admin login zaroori hai.' });
  }
  try {
    const decoded = verifyToken(token, ADMIN_AUDIENCE);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access Denied! Tum admin nahi ho.' });
    }
    const admin = await loadAdmin(decoded);
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Admin session expire. Dobara login karein.' });
    }
    req.user = { id: admin._id.toString(), username: admin.username, role: 'admin' };
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Admin session expire. Dobara login karein.' });
  }
};

module.exports = { signUser, signAdmin, requireAuth, requireAdmin };
