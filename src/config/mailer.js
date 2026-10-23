const nodemailer = require('nodemailer');

let transporter = null;

const getTransporter = () => {
  if (transporter) return transporter;
  // SMTP_* env set nahi hai toh email nahi bheja ja sakta
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    // P1 #23: SMTP hang ho toh request kabhi na latke (pehle indefinite tha)
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 20000,
    // Gmail App Password groups of 4 me dikhta hai — spaces hatao, warna auth fail
    auth: {
      user: String(process.env.SMTP_USER || '').trim(),
      pass: String(process.env.SMTP_PASS || '').replace(/\s+/g, '')
    }
  });
  return transporter;
};

// Password-reset OTP email. SMTP configure na ho toh EMAIL_NOT_CONFIGURED
// throw karta hai (caller 503 dega). Production me OTP kabhi log nahi hota.
const sendOtpEmail = async (to, otp) => {
  const tx = getTransporter();
  if (!tx) {
    if (process.env.NODE_ENV !== 'production') {
      console.log(`📧 [DEV-ONLY] OTP for ${to}: ${otp}`);
    }
    const err = new Error('EMAIL_NOT_CONFIGURED');
    err.code = 'EMAIL_NOT_CONFIGURED';
    throw err;
  }
  await tx.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject: 'RoomKhojo — Password Reset OTP',
    text: `Aapka RoomKhojo password-reset OTP hai: ${otp}\nYe OTP 10 minute me expire ho jayega. Kisi ke saath share na karein.\nAgar aapne ye request nahi ki thi toh ignore kar dein.`
  });
};

module.exports = { sendOtpEmail };
