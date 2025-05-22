require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const https = require('https');
const fs = require('fs');

const app = express();
app.use(express.json());

// Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// SSL/TLS configuration (using self-signed certificates for testing)
const privateKey = fs.readFileSync('key.pem', 'utf8');
const certificate = fs.readFileSync('cert.pem', 'utf8');
const credentials = { key: privateKey, cert: certificate };
const httpsServer = https.createServer(credentials, app);

// Root endpoint (placeholder)
app.get('/', (req, res) => {
  res.json({ message: 'EPIC Server is running with Supabase. Endpoints to be implemented.' });
});

// Start server
const PORT = 443;
httpsServer.listen(PORT, () => {
  console.log(`Server running on https://localhost:${PORT}`);
});