const crypto = require('crypto');
const AuditLog = require('../models/AuditLog');
const RoomArchive = require('../models/RoomArchive');

const hashIp = (req) => {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip = forwarded || req.ip || '';
  if (!ip) return '';
  return crypto.createHash('sha256').update(ip).digest('hex').slice(0, 32);
};

const logAudit = async (req, { action, targetType = '', targetId = '', details = {}, actorRole, actorId } = {}) => {
  try {
    await AuditLog.create({
      actorId: String(actorId || (req.user && req.user.id) || ''),
      actorRole: actorRole || (req.user && req.user.role) || 'system',
      action: String(action || 'unknown').slice(0, 80),
      targetType: String(targetType || '').slice(0, 40),
      targetId: String(targetId || '').slice(0, 80),
      ipHash: hashIp(req),
      details
    });
  } catch (error) {
    console.error('Audit log failed:', error.message);
  }
};

const archiveRooms = async (rooms, { deletedBy = '', deletedByRole = 'system', reason = '' } = {}) => {
  const list = (Array.isArray(rooms) ? rooms : [rooms]).filter(Boolean);
  if (!list.length) return 0;
  try {
    await RoomArchive.insertMany(list.slice(0, 1000).map((room) => ({
      originalId: room._id || room.id,
      room,
      deletedBy: String(deletedBy || '').slice(0, 80),
      deletedByRole,
      reason: String(reason || '').slice(0, 200)
    })), { ordered: false });
    return list.length;
  } catch (error) {
    console.error('Room archive failed:', error.message);
    return 0;
  }
};

module.exports = { logAudit, archiveRooms, hashIp };
