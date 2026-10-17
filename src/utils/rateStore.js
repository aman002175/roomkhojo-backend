// 🚦 Upstash Redis rate-limit store (OPTIONAL — env vars set hone par active)
//
// Kyun: Vercel serverless par har instance ka apna MemoryStore hota hai, isliye
// attacker instance badal ke rate-limit bypass kar sakta hai. Upstash (HTTP Redis)
// ek shared counter rakhta hai — sirf GINTI (rate-limit counters), data nahi.
// Rooms/users/ads hamesha MongoDB se hi aate hain — yahan koi app-data cache NAHI hai.
//
// Env vars (Vercel → backend project → Environment Variables):
//   UPSTASH_REDIS_REST_URL   = https://xxx.upstash.io
//   UPSTASH_REDIS_REST_TOKEN = Axxxx...
//
// Env vars na hon (ya Redis down ho) → purana MemoryStore / fail-open (app kabhi na rukey).
const rateLimit = require('express-rate-limit');

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const upstashEnabled = Boolean(UPSTASH_URL && UPSTASH_TOKEN);

// Upstash REST: ek HTTP call me multiple commands (INCR + EXPIRE atomic-ish)
const upstashPipeline = async (cmds) => {
  const res = await fetch(`${UPSTASH_URL}/pipeline`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${UPSTASH_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmds),
    signal: AbortSignal.timeout(2500) // Redis slow ho toh request latak na jaye
  });
  if (!res.ok) throw new Error(`Upstash ${res.status}`);
  return res.json();
};

class UpstashStore {
  constructor(prefix) { this.prefix = prefix; this.windowMs = 15 * 60 * 1000; }
  init(options) { this.windowMs = (options && options.windowMs) || this.windowMs; }
  key(k) { return `rk:rl:${this.prefix}:${k}`; }
  // express-rate-limit increment() ka result mangta hai: {totalHits, resetTime}
  async increment(key) {
    const ms = this.windowMs;
    try {
      const out = await upstashPipeline([
        ['INCR', this.key(key)],
        ['EXPIRE', this.key(key), Math.ceil(ms / 1000), 'NX'] // TTL sirf pehli baar (NX) — count kabhi permanent nahi
      ]);
      const totalHits = Number((out && out[0] && out[0].result) || 1) || 1;
      return { totalHits, resetTime: new Date(Date.now() + ms) };
    } catch {
      // Fail-open: Redis down hai toh request allow karo (limit na lagne se better hai app crash na ho)
      return { totalHits: 1, resetTime: new Date(Date.now() + ms) };
    }
  }
  async get(key) {
    try {
      const out = await upstashPipeline([['GET', this.key(key)]]);
      const v = out && out[0] ? out[0].result : null;
      return v == null ? undefined : { totalHits: Number(v) || 1, resetTime: new Date(Date.now() + this.windowMs) };
    } catch { return undefined; }
  }
  async decrement(key) {
    try { await upstashPipeline([['DECR', this.key(key)]]); } catch { /* fail silent */ }
  }
  async resetKey(key) {
    try { await upstashPipeline([['DEL', this.key(key)]]); } catch { /* fail silent */ }
  }
}

// Limiter factory: Upstash configured → shared store; warna default MemoryStore (jaisa pehle tha)
const createLimiter = (prefix, options) => {
  if (!upstashEnabled) return rateLimit(options);
  return rateLimit({ ...options, store: new UpstashStore(prefix) });
};

module.exports = { createLimiter, upstashEnabled };
