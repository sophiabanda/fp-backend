import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import users from './users.js';
import { unsealEventsResponse } from '@fingerprintjs/fingerprintjs-pro-server-api';

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

const decryptionKey = process.env.BASE64_KEY;

if (!decryptionKey) {
  console.error('Please set BASE64_KEY in your .env file');
  process.exit(1);
}

app.post('/login', (req, res) => {
  const { username, password, visitorId } = req.body;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const idMatch = user.visitorId.includes(visitorId);

  res.json({
    success: true,
    user: username,
    idMatch,
    message: idMatch
      ? 'Login successful'
      : 'Login successful but unknown device',
  });
});

app.post('/trust-device', (req, res) => {
  const { username, visitorId } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user || user.visitorId.includes(visitorId)) {
    return res.status(400).json({ error: 'Invalid user or already trusted' });
  }

  user.visitorId.push(visitorId);
  res.json({ success: true, message: 'Device trusted' });
});

app.post('/sealed', async (req, res) => {
  try {
    const { sealed } = req.body;

    if (!sealed) {
      return res
        .status(400)
        .json({ error: 'Missing sealedResult in request body' });
    }

    const unsealedData = await unsealEventsResponse(
      Buffer.from(sealed, 'base64'),
      [
        {
          key: Buffer.from(decryptionKey, 'base64'),
          algorithm: 'aes-256-gcm',
        },
      ]
    );

    res.json({ success: true, data: unsealedData });
  } catch (error) {
    console.error('Error during decryption:', error);
    res.status(500).json({ error: 'Failed to decrypt sealedResult' });
  }
});

const PORT = process.env.PORT || 5001;
const HOST = '127.0.0.1';
app.listen(PORT, HOST, () => console.log(`Server running on port ${PORT}`));
