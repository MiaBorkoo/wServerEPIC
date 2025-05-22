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

// API Endpoints

// Root endpoint (placeholder)
app.get('/', (req, res) => {
    res.json({ message: 'EPIC Server is running with Supabase.' });
  });
  
  // User Registration: POST /api/auth/register
  app.post('/api/auth/register', async (req, res) => {
    const { username, hashed_password, salt, encrypted_mek, public_key } = req.body;
  
    const { data, error } = await supabase
      .from('Users')
      .insert({
        username,
        hashed_password,
        salt,
        totp_secret: null, 
        public_key
      })
      .select('id')
      .single();
  
    if (error) {
      return res.status(400).json({ status: 'error', message: error.message });
    }
  
    // Optionally store encrypted_mek elsewhere or handle differently
    // For now, return user ID
    res.json({ status: 'success', user_id: data.id });
  });
  
  // Get Salts: GET /api/user/:username/salts
  app.get('/api/user/:username/salts', async (req, res) => {
    const { username } = req.params;
  
    const { data, error } = await supabase
      .from('Users')
      .select('salt')
      .eq('username', username)
      .single();
  
    if (error || !data) {
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }
    res.json({ salt: data.salt });
  });
  
  // First-Factor Login: POST /api/auth/login/first-factor
  app.post('/api/auth/login/first-factor', async (req, res) => {
    const { username, hashed_password } = req.body;
  
    const { data, error } = await supabase
      .from('Users')
      .select('id, hashed_password, totp_secret')
      .eq('username', username)
      .single();
  
    if (error || !data || data.hashed_password !== hashed_password) {
      return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
    }
  
    const temp_session = crypto.randomBytes(16).toString('hex');
    const totp_required = !!data.totp_secret; 
    res.json({ temp_session, totp_required });
  });
  
  // Second-Factor Login: POST /api/auth/totp/second-factor
  app.post('/api/auth/totp/second-factor', async (req, res) => {
    const { temp_session, totp } = req.body;
  
    // Placeholder: Integrate with a TOTP library (e.g., otplib) to verify TOTP
    // For now, assume TOTP is valid for testing
    if (totp === '123456') { // Replace with actual TOTP validation
      const session_id = crypto.randomBytes(16).toString('hex');
      res.json({ session: session_id });
    } else {
      res.status(401).json({ status: 'error', message: 'Invalid TOTP' });
    }
  });
  
  // File Upload: POST /api/files/upload
  app.post('/api/files/upload', async (req, res) => {
    const { owner_id, name, size, encrypted_file, integrity_hash } = req.body;
  
    const { data, error } = await supabase
      .from('Files')
      .insert({
        owner_id,
        name,
        size,
        encrypted_file,
        integrity_hash,
        created_at: new Date().toISOString()
      })
      .select('file_uuid')
      .single();
  
    if (error) {
      return res.status(400).json({ status: 'error', message: error.message });
    }
    res.json({ status: 'success', file_uuid: data.file_uuid });
  });
  
  // Share File: POST /api/files/share
  app.post('/api/files/share', async (req, res) => {
    const { owner_id, recipient_id, file_id, encrypted_file_key, time_limit } = req.body;
  
    const { data, error } = await supabase
      .from('Shared')
      .insert({
        owner_id,
        recipient_id,
        file_id,
        encrypted_file_key,
        shared_at: new Date().toISOString(),
        time_limit, 
      })
      .select('shared_id')
      .single();
  
    if (error) {
      return res.status(400).json({ status: 'error', message: error.message });
    }
    res.json({ status: 'success', shared_id: data.shared_id });
  });
  
  // List Files: GET /api/files
  app.get('/api/files', async (req, res) => {
    const { user_id } = req.query; // Owner or shared files for this user
  
    // Owned files
    const { data: ownedFiles, error: ownedError } = await supabase
      .from('Files')
      .select('file_uuid, name, size, created_at, integrity_hash')
      .eq('owner_id', user_id);
  
    // Shared files
    const { data: sharedFiles, error: sharedError } = await supabase
      .from('Shared')
      .select('Files(file_uuid, name, size, created_at, integrity_hash), encrypted_file_key')
      .eq('recipient_id', user_id);
  
    if (ownedError || sharedError) {
      return res.status(400).json({ status: 'error', message: ownedError?.message || sharedError?.message });
    }
    res.json({ owned: ownedFiles, shared: sharedFiles });
  });
  
  // Start server
  const PORT = 443;
  httpsServer.listen(PORT, () => {
    console.log(`Server running on https://localhost:${PORT}`);
  });