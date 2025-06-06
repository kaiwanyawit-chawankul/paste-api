import express from 'express';
import cors from 'cors';
import { neon } from '@neondatabase/serverless';
import { randomBytes } from 'crypto';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import CryptoJS from 'crypto-js';

dotenv.config();

const sql = neon(process.env.DATABASE_URL);

// Encryption helper functions
const encryptContent = (content, password) => {
  return CryptoJS.AES.encrypt(content, password).toString();
};

const decryptContent = (encryptedContent, password) => {
  const bytes = CryptoJS.AES.decrypt(encryptedContent, password);
  return bytes.toString(CryptoJS.enc.Utf8);
};

// Initialize database schema and run migrations
async function initializeSchema() {
  try {
    // Create initial table
    await sql`
      CREATE TABLE IF NOT EXISTS pastes (
        id TEXT PRIMARY KEY,
        content TEXT NOT NULL,
        language TEXT DEFAULT 'plain',
        expires_at TIMESTAMP,
        burn_after_read BOOLEAN DEFAULT false,
        is_private BOOLEAN DEFAULT false,
        views INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        deleted BOOLEAN DEFAULT false
      );
    `;

    // Add is_encrypted column
    await sql`
      ALTER TABLE pastes
      ADD COLUMN IF NOT EXISTS is_encrypted BOOLEAN DEFAULT false;
    `;

    console.log('Schema and migrations completed successfully');
  } catch (error) {
    console.error('Error in database setup:', error);
    process.exit(1);
  }
}

const app = express();

// Trust proxy - required for rate limiting behind reverse proxies (like on Render.com)
app.set('trust proxy', 1);

// Middleware
app.use(express.json());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Basic health check route
app.get('/healthz', (req, res) => {
  res.json({ status: 'ok' });
});

// Create paste
app.post('/api/pastes', async (req, res) => {
  try {
    const { content, expiresIn, language, burnAfterRead, isPrivate, password } = req.body;
    const id = randomBytes(4).toString('hex');
    const expirationDate = expiresIn ? new Date(Date.now() + expiresIn) : null;

    // Encrypt content if password is provided
    const isEncrypted = !!password;
    const finalContent = isEncrypted ? encryptContent(content, password) : content;

    await sql`
      INSERT INTO pastes (
        id, content, language, expires_at, burn_after_read, is_private, is_encrypted, views
      )
      VALUES (
        ${id}, ${finalContent}, ${language}, ${expirationDate}, ${burnAfterRead}, ${isPrivate}, ${isEncrypted}, 0
      )
    `;

    res.json({ id });
  } catch (error) {
    console.error('Error creating paste:', error);
    res.status(500).json({ error: 'Failed to create paste' });
  }
});

// Get paste by ID
app.get('/api/pastes/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.query;

    // Get the paste first
    const [paste] = await sql`
      SELECT * FROM pastes
      WHERE id = ${id}
        AND (expires_at IS NULL OR expires_at > NOW())
        AND NOT deleted
    `;

    if (!paste) {
      return res.status(404).json({ error: 'Paste not found' });
    }

    // Check if paste is encrypted and password is required
    if (paste.is_encrypted && !password) {
      return res.status(401).json({ error: 'Password required for encrypted paste' });
    }

    // Try to decrypt if the paste is encrypted
    if (paste.is_encrypted) {
      try {
        paste.content = decryptContent(paste.content, password);
      } catch (error) {
        return res.status(401).json({ error: 'Invalid password' });
      }
    }

    // Increment views
    await sql`
      UPDATE pastes
      SET views = views + 1
      WHERE id = ${id}
    `;

    // Handle burn after read
    if (paste.burn_after_read && paste.views >=1) {
      await sql`
        UPDATE pastes
        SET deleted = true
        WHERE id = ${id}
      `;
    }

    res.json(paste);
  } catch (error) {
    console.error('Error fetching paste:', error);
    res.status(500).json({ error: 'Failed to fetch paste' });
  }
});

// Get all pastes
app.get('/api/pastes', async (req, res) => {
  try {
    const pastes = await sql`
      SELECT
        id,
        CASE
          WHEN is_encrypted THEN '[Encrypted Content]'
          ELSE SUBSTRING(content, 1, 100) || CASE WHEN LENGTH(content) > 100 THEN '...' ELSE '' END
        END as content,
        language,
        created_at,
        views,
        is_private,
        burn_after_read,
        expires_at
      FROM pastes
      WHERE NOT deleted
        AND (expires_at IS NULL OR expires_at > NOW())
      ORDER BY created_at DESC
      LIMIT 100
    `;

    // Filter out private pastes content
    const safePastes = pastes.map(paste => ({
      ...paste,
      content: paste.is_encrypted ? '[Encrypted]' : paste.content + (paste.content.length > 100 ? '...' : ''),
      isPrivate: paste.is_private,
      isEncrypted: paste.is_encrypted,
      burnAfterRead: paste.burn_after_read,
      createdAt: paste.created_at,
      expiresAt: paste.expires_at
    }));

    res.json(safePastes);
  } catch (error) {
    console.error('Error fetching pastes:', error);
    res.status(500).json({ error: 'Failed to fetch pastes' });
  }
});

// Preview paste by ID (without decrypting)
app.get('/api/preview/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Get the paste first
    const [paste] = await sql`
      SELECT
        id,
        CASE
          WHEN is_encrypted THEN '[Encrypted Content]'
          ELSE SUBSTRING(content, 1, 100) || CASE WHEN LENGTH(content) > 100 THEN '...' ELSE '' END
        END as content,
        language,
        expires_at,
        burn_after_read,
        is_private,
        is_encrypted,
        views,
        created_at
      FROM pastes
      WHERE id = ${id}
        AND (expires_at IS NULL OR expires_at > NOW())
        AND NOT deleted
    `;

    if (!paste) {
      return res.status(404).json({ error: 'Paste not found' });
    }

    // Format the response
    const preview = {
      ...paste,
      isPrivate: paste.is_private,
      isEncrypted: paste.is_encrypted,
      burnAfterRead: paste.burn_after_read,
      createdAt: paste.created_at,
      expiresAt: paste.expires_at
    };

    res.json(preview);
  } catch (error) {
    console.error('Error fetching paste preview:', error);
    res.status(500).json({ error: 'Failed to fetch paste preview' });
  }
});

// Delete paste by ID
app.delete('/api/pastes/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Check if paste exists
    const [paste] = await sql`
      SELECT id FROM pastes
      WHERE id = ${id}
        AND NOT deleted
    `;

    if (!paste) {
      return res.status(404).json({ error: 'Paste not found' });
    }

    // Soft delete the paste
    await sql`
      UPDATE pastes
      SET deleted = true
      WHERE id = ${id}
    `;

    res.status(200).json({ message: 'Paste deleted successfully' });
  } catch (error) {
    console.error('Error deleting paste:', error);
    res.status(500).json({ error: 'Failed to delete paste' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something broke!' });
});

// Initialize schema before starting the server
initializeSchema()
  .then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });

// Export for potential serverless deployment
export default app;
