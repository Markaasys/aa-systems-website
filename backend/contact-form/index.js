const { GoogleAuth } = require('google-auth-library');

const SERVICE_ACCOUNT_EMAIL = 'contact-form-sender@dubdubdub-502800.iam.gserviceaccount.com';
const IMPERSONATED_USER = 'os@aa-systems.ai';
const SEND_AS = 'chuck@aa-systems.ai';
const TO_ADDRESS = 'hello@aa-systems.ai';
// localhost is allowed so the form can be tested against the live function during local dev.
const ALLOWED_ORIGINS = new Set(['https://aa-systems.ai', 'http://localhost:3001']);

const auth = new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/cloud-platform'] });

function setCors(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.has(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
  }
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
}

function isValidEmail(value) {
  return typeof value === 'string' && value.length <= 320 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

async function verifyTurnstile(token, remoteIp) {
  const params = new URLSearchParams({
    secret: process.env.TURNSTILE_SECRET_KEY,
    response: token,
    remoteip: remoteIp || '',
  });
  const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
  });
  const data = await resp.json();
  return data.success === true;
}

async function getDelegatedAccessToken() {
  const client = await auth.getClient();
  const iamToken = await client.getAccessToken();

  const now = Math.floor(Date.now() / 1000);
  const claimSet = {
    iss: SERVICE_ACCOUNT_EMAIL,
    sub: IMPERSONATED_USER,
    scope: 'https://www.googleapis.com/auth/gmail.send',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };

  const signResp = await fetch(
    `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${SERVICE_ACCOUNT_EMAIL}:signJwt`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${iamToken.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ payload: JSON.stringify(claimSet) }),
    }
  );
  if (!signResp.ok) {
    throw new Error(`signJwt failed: ${signResp.status} ${await signResp.text()}`);
  }
  const { signedJwt } = await signResp.json();

  const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: signedJwt,
    }),
  });
  if (!tokenResp.ok) {
    throw new Error(`token exchange failed: ${tokenResp.status} ${await tokenResp.text()}`);
  }
  const { access_token } = await tokenResp.json();
  return access_token;
}

function buildRawMessage({ name, email, message }) {
  const lines = [
    `From: Chuck <${SEND_AS}>`,
    `To: ${TO_ADDRESS}`,
    `Reply-To: ${email}`,
    `Subject: New inquiry from ${name} via aa-systems.ai`,
    'Content-Type: text/plain; charset=UTF-8',
    '',
    `Name: ${name}`,
    `Email: ${email}`,
    '',
    message,
  ];
  const raw = lines.join('\r\n');
  return Buffer.from(raw).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sendEmail(fields) {
  const accessToken = await getDelegatedAccessToken();
  const resp = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ raw: buildRawMessage(fields) }),
  });
  if (!resp.ok) {
    throw new Error(`Gmail send failed: ${resp.status} ${await resp.text()}`);
  }
}

exports.contactForm = async (req, res) => {
  setCors(req, res);

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }
  if (req.method !== 'POST') {
    res.status(405).json({ success: false, error: 'Method not allowed' });
    return;
  }

  const { name, email, message, turnstileToken, website } = req.body || {};

  // Honeypot: real visitors never fill this hidden field in.
  if (website) {
    res.status(200).json({ success: true });
    return;
  }

  if (!name || !message || !isValidEmail(email) || name.length > 200 || message.length > 5000) {
    res.status(400).json({ success: false, error: 'Please fill in all fields with a valid email.' });
    return;
  }

  if (!turnstileToken) {
    res.status(400).json({ success: false, error: 'Verification failed. Please try again.' });
    return;
  }

  try {
    const remoteIp = req.headers['x-forwarded-for'] || req.ip;
    const turnstileOk = await verifyTurnstile(turnstileToken, remoteIp);
    if (!turnstileOk) {
      res.status(400).json({ success: false, error: 'Verification failed. Please try again.' });
      return;
    }

    await sendEmail({ name, email, message });
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('contactForm error:', err);
    res.status(500).json({ success: false, error: 'Something went wrong. Please email hello@aa-systems.ai directly.' });
  }
};
