// Public listing projection: contact/payment/ownership/audit fields kabhi
// public ya favorites response me nahi jaate.
const PUBLIC_ROOM_EXCLUDE = [
  '-reportedBy',
  '-viewKeys',
  '-mobile',
  '-userId',
  '-owner',
  '-paymentRef',
  '-paymentCode',
  '-bannerRef',
  '-bannerAmount',
  '-paymentAmount',
  '-complimentary',
  '-claimRequestedBy',
  '-claimRequestName',
  '-claimRequestedAt',
  '-serviceDailyRate',
  '-serviceFee',
  '-googleMapUrl',
  '-rejectReason',
  '-idempotencyKey'
].join(' ');

module.exports = { PUBLIC_ROOM_EXCLUDE };
