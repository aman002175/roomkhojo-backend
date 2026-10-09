const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}, { timestamps: true });

// Password save hone se pehle hash hoga — plain password kabhi DB me nahi jayega
adminSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Legacy migration: puraane plaintext passwords (Render-era) pehli
// successful login par auto-hash ho jaate hain. Uske baad bcrypt hi chalega.
adminSchema.methods.comparePassword = async function (plainPassword) {
  const input = plainPassword || '';
  if (await bcrypt.compare(input, this.password)) return true;
  if (this.password && input && this.password === input) {
    this.password = input; // pre-save hook ise hash karke save karega
    await this.save();
    return true;
  }
  return false;
};

module.exports = mongoose.model('Admin', adminSchema);
