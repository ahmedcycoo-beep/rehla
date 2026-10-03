const crypto = require('crypto');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const password = String((req.body && req.body.password) || '');
  const expected = process.env.RAHHAL_ADMIN_PASSWORD || '';
  if (!expected || password.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(password), Buffer.from(expected))) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = crypto.createHmac('sha256', expected).update(ts).digest('hex');
  const token = Buffer.from(`${ts}.${sig}`).toString('base64url');
  return res.status(200).json({ token });
};
