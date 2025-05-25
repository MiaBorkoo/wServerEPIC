// Global state
let currentUser = null;
let sessionToken = null;
let tempToken = null;

// DOM elements
let elements = {};

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeElements();
    setupEventListeners();
    updateUI();
});

function initializeElements() {
    // Cache all DOM elements for better performance
    elements = {
        authStatus: document.getElementById('auth-status'),
        authSection: document.getElementById('auth-section'),
        fileSection: document.getElementById('file-section'),
        sharingSection: document.getElementById('sharing-section'),
        verificationSection: document.getElementById('verification-section'),
        responseLog: document.getElementById('response-log'),
        
        // Forms
        registerForm: document.getElementById('register-form'),
        loginForm: document.getElementById('login-form'),
        totpForm: document.getElementById('totp-form'),
        changePasswordForm: document.getElementById('change-password-form'),
        uploadForm: document.getElementById('upload-form'),
        fileOpsForm: document.getElementById('file-ops-form'),
        shareForm: document.getElementById('share-form'),
        mySharesForm: document.getElementById('my-shares-form'),
        revokeForm: document.getElementById('revoke-form'),
        pubkeyForm: document.getElementById('pubkey-form'),
        verifyGenerateForm: document.getElementById('verify-generate-form'),
        verifyConfirmForm: document.getElementById('verify-confirm-form'),
        
        // Lists and displays
        filesList: document.getElementById('files-list'),
        mySharesList: document.getElementById('my-shares-list'),
        receivedSharesList: document.getElementById('received-shares-list'),
        pubkeyResult: document.getElementById('pubkey-result'),
        verifyCodeResult: document.getElementById('verify-code-result'),
        
        // Buttons
        logoutBtn: document.getElementById('logout-btn'),
        refreshFiles: document.getElementById('refresh-files'),
        refreshReceivedShares: document.getElementById('refresh-received-shares'),
        downloadBtn: document.getElementById('download-btn'),
        deleteBtn: document.getElementById('delete-btn'),
        metadataBtn: document.getElementById('metadata-btn'),
        clearLog: document.getElementById('clear-log')
    };
}

function setupEventListeners() {
    // Authentication
    elements.registerForm.addEventListener('submit', handleRegister);
    elements.loginForm.addEventListener('submit', handleLogin);
    elements.totpForm.addEventListener('submit', handleTOTP);
    elements.changePasswordForm.addEventListener('submit', handleChangePassword);
    elements.logoutBtn.addEventListener('click', handleLogout);
    
    // File management
    elements.uploadForm.addEventListener('submit', handleFileUpload);
    elements.refreshFiles.addEventListener('click', refreshFilesList);
    elements.downloadBtn.addEventListener('click', handleFileDownload);
    elements.deleteBtn.addEventListener('click', handleFileDelete);
    elements.metadataBtn.addEventListener('click', handleFileMetadata);
    
    // Sharing
    elements.shareForm.addEventListener('submit', handleFileShare);
    elements.mySharesForm.addEventListener('submit', handleGetFileShares);
    elements.refreshReceivedShares.addEventListener('click', refreshReceivedShares);
    elements.revokeForm.addEventListener('submit', handleRevokeShare);
    
    // Verification
    elements.pubkeyForm.addEventListener('submit', handleGetPublicKey);
    elements.verifyGenerateForm.addEventListener('submit', handleGenerateVerification);
    elements.verifyConfirmForm.addEventListener('submit', handleConfirmVerification);
    
    // Utility
    elements.clearLog.addEventListener('click', clearResponseLog);
}

// API utility functions
async function makeApiCall(method, endpoint, data = null, useToken = true, pathParams = {}) {
    const url = getApiUrl(endpoint, pathParams);
    
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
        }
    };
    
    if (useToken && sessionToken) {
        options.headers['Authorization'] = `Bearer ${sessionToken}`;
    } else if (useToken && tempToken) {
        options.headers['Authorization'] = `Bearer ${tempToken}`;
    }
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    try {
        logApiCall(method, url, data);
        const response = await fetch(url, options);
        const responseData = await response.json();
        
        logApiResponse(response.status, responseData);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${responseData.detail || 'Unknown error'}`);
        }
        
        return responseData;
    } catch (error) {
        logApiResponse('ERROR', { error: error.message });
        throw error;
    }
}

async function uploadFile(endpoint, fileData, additionalData = {}) {
    const url = getApiUrl(endpoint);
    
    const formData = new FormData();
    formData.append('file', fileData);
    
    // Add additional data fields
    for (const [key, value] of Object.entries(additionalData)) {
        formData.append(key, value);
    }
    
    const options = {
        method: 'POST',
        headers: {}
    };
    
    if (sessionToken) {
        options.headers['Authorization'] = `Bearer ${sessionToken}`;
    }
    
    options.body = formData;
    
    try {
        logApiCall('POST', url, { file: fileData.name, ...additionalData });
        const response = await fetch(url, options);
        const responseData = await response.json();
        
        logApiResponse(response.status, responseData);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${responseData.detail || 'Unknown error'}`);
        }
        
        return responseData;
    } catch (error) {
        logApiResponse('ERROR', { error: error.message });
        throw error;
    }
}

// Authentication handlers
async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;
    const totpSecret = document.getElementById('reg-totp-secret').value || CONFIG.DEFAULT_TOTP_SECRET;
    
    try {
        // Generate salts (32-byte random values)
        const authSalt = generateRandomBytes(32);
        const encSalt = generateRandomBytes(32);
        
        // Generate fake derived keys (in real implementation, would use Argon2id)
        const authKey = generateFakeHash(password + authSalt);
        const encryptionKey = generateFakeHash(password + encSalt);
        
        // Generate fake encrypted MEK (Master Encryption Key)
        const fakeMEK = generateRandomBytes(32);
        const encryptedMEK = generateFakeEncryption(fakeMEK, encryptionKey);
        
        // Generate fake public key (in real implementation, would be actual RSA/EC key)
        const fakePublicKey = generateFakePublicKey();
        
        // Prepare user data for HMAC computation
        const userData = {
            username,
            auth_salt: authSalt,
            enc_salt: encSalt,
            auth_key: authKey,
            encrypted_mek: encryptedMEK,
            totp_secret: totpSecret,
            public_key: fakePublicKey
        };
        
        // Generate HMAC for user data integrity protection (client-side computation)
        const userDataHmac = generateFakeHMAC(userData);
        
        const response = await makeApiCall('POST', CONFIG.ENDPOINTS.REGISTER, {
            ...userData,
            user_data_hmac: userDataHmac
        }, false);
        
        alert('Registration successful!');
        elements.registerForm.reset();
    } catch (error) {
        alert(`Registration failed: ${error.message}`);
    }
}

// Helper functions for fake crypto operations (for testing only!)
function generateRandomBytes(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

function generateFakeHash(input) {
    // Fake hash for testing - NOT cryptographically secure!
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
        const char = input.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    return 'fake_hash_' + Math.abs(hash).toString(16);
}

function generateFakeEncryption(data, key) {
    // Fake encryption for testing - NOT secure!
    return 'encrypted_' + btoa(data + '_with_key_' + key);
}

function generateFakePublicKey() {
    // Fake public key for testing
    return {
        kty: "RSA",
        n: "fake_modulus_" + generateRandomBytes(16),
        e: "AQAB",
        use: "sig",
        kid: "fake_key_id_" + Date.now()
    };
}

function generateFakeHMAC(userData) {
    // Fake HMAC computation for testing - NOT cryptographically secure!
    // In real implementation, would use proper HMAC-SHA256 with secret key
    const dataString = JSON.stringify(userData);
    let hash = 0;
    for (let i = 0; i < dataString.length; i++) {
        const char = dataString.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return 'test_hmac_' + Math.abs(hash).toString(16) + '_' + Date.now();
}

async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    
    try {
        // First, get user salts
        const saltsResponse = await makeApiCall('GET', CONFIG.ENDPOINTS.SALTS, null, false, { username });
        
        // Derive auth key using the server-provided salt (fake implementation for testing)
        const authKey = generateFakeHash(password + saltsResponse.auth_salt);
        
        // Then perform login
        const loginResponse = await makeApiCall('POST', CONFIG.ENDPOINTS.LOGIN, {
            username,
            auth_key: authKey, // Send derived key instead of raw password
            nonce: 'test-nonce-' + Date.now()
        }, false);
        
        tempToken = loginResponse.temp_token;
        currentUser = username;
        
        // Show TOTP form
        elements.totpForm.style.display = 'block';
        elements.loginForm.style.display = 'none';
        
    } catch (error) {
        alert(`Login failed: ${error.message}`);
    }
}

async function handleTOTP(e) {
    e.preventDefault();
    
    const totpCode = document.getElementById('totp-code').value;
    
    try {
        const response = await makeApiCall('POST', CONFIG.ENDPOINTS.TOTP, {
            username: currentUser,
            totp_code: totpCode
        }, true);
        
        sessionToken = response.session_token;
        tempToken = null;
        
        updateUI();
        alert('Login successful!');
        
        // Reset forms
        elements.loginForm.reset();
        elements.totpForm.reset();
        elements.totpForm.style.display = 'none';
        elements.loginForm.style.display = 'block';
        
    } catch (error) {
        alert(`TOTP verification failed: ${error.message}`);
    }
}

async function handleChangePassword(e) {
    e.preventDefault();
    
    const newPassword = document.getElementById('new-password').value;
    const totpCode = document.getElementById('change-totp').value;
    
    try {
        // Generate new salts for the new password
        const newAuthSalt = generateRandomBytes(32);
        const newEncSalt = generateRandomBytes(32);
        
        // Generate new derived keys
        const newAuthKey = generateFakeHash(newPassword + newAuthSalt);
        const newEncryptionKey = generateFakeHash(newPassword + newEncSalt);
        
        // Generate new encrypted MEK (in real implementation, would re-encrypt existing MEK)
        const fakeMEK = generateRandomBytes(32);
        const newEncryptedMEK = generateFakeEncryption(fakeMEK, newEncryptionKey);
        
        await makeApiCall('POST', CONFIG.ENDPOINTS.CHANGE_PASSWORD, {
            new_auth_salt: newAuthSalt,
            new_enc_salt: newEncSalt,
            new_auth_key: newAuthKey,
            new_encrypted_mek: newEncryptedMEK,
            totp_code: totpCode
        });
        
        alert('Password changed successfully!');
        elements.changePasswordForm.reset();
        
    } catch (error) {
        alert(`Password change failed: ${error.message}`);
    }
}

async function handleLogout() {
    try {
        await makeApiCall('POST', CONFIG.ENDPOINTS.LOGOUT);
    } catch (error) {
        console.log('Logout error (ignoring):', error.message);
    }
    
    currentUser = null;
    sessionToken = null;
    tempToken = null;
    updateUI();
    alert('Logged out successfully!');
}

// File management handlers
async function handleFileUpload(e) {
    e.preventDefault();
    
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Please select a file');
        return;
    }
    
    try {
        // Generate a UUID for the file (in real app, this would be done server-side)
        const fileId = 'file-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
        
        const response = await uploadFile(CONFIG.ENDPOINTS.FILE_UPLOAD, file, {
            file_id: fileId,
            filename_encrypted: btoa(file.name), // Base64 encode for testing
            file_size_encrypted: btoa(file.size.toString()),
            file_data_hmac: 'test-hmac-' + Date.now()
        });
        
        alert('File uploaded successfully!');
        fileInput.value = '';
        refreshFilesList();
        
    } catch (error) {
        alert(`File upload failed: ${error.message}`);
    }
}

async function refreshFilesList() {
    try {
        const response = await makeApiCall('GET', CONFIG.ENDPOINTS.FILES_LIST);
        const allFiles = [...(response.owned_files || []), ...(response.shared_files || [])];
        displayFilesList(allFiles);
    } catch (error) {
        alert(`Failed to refresh files: ${error.message}`);
    }
}

function displayFilesList(files) {
    elements.filesList.innerHTML = '';
    
    if (files.length === 0) {
        elements.filesList.innerHTML = '<p>No files found</p>';
        return;
    }
    
    files.forEach(file => {
        const fileDiv = document.createElement('div');
        fileDiv.className = 'file-item';
        fileDiv.innerHTML = `
            <strong>File ID:</strong> ${file.file_id}<br>
            <strong>Filename:</strong> ${file.filename_encrypted || 'N/A'}<br>
            <strong>Size:</strong> ${file.file_size_encrypted || 'N/A'}<br>
            <strong>Uploaded:</strong> ${new Date(file.upload_timestamp * 1000).toLocaleString()}<br>
        `;
        elements.filesList.appendChild(fileDiv);
    });
}

async function handleFileDownload() {
    const fileId = document.getElementById('file-id-input').value.trim();
    
    if (!fileId) {
        alert('Please enter a file ID');
        return;
    }
    
    try {
        const url = getApiUrl(CONFIG.ENDPOINTS.FILE_DOWNLOAD, { file_id: fileId });
        
        const options = {
            method: 'GET',
            headers: {}
        };
        
        if (sessionToken) {
            options.headers['Authorization'] = `Bearer ${sessionToken}`;
        }
        
        logApiCall('GET', url, null);
        const response = await fetch(url, options);
        
        if (!response.ok) {
            const errorData = await response.json();
            logApiResponse(response.status, errorData);
            throw new Error(`HTTP ${response.status}: ${errorData.detail || 'Unknown error'}`);
        }
        
        // Handle binary file download
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = downloadUrl;
        a.download = fileId;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
        
        logApiResponse(response.status, { message: 'File downloaded successfully' });
        alert('File download successful!');
        
    } catch (error) {
        alert(`File download failed: ${error.message}`);
    }
}

async function handleFileDelete() {
    const fileId = document.getElementById('file-id-input').value.trim();
    
    if (!fileId) {
        alert('Please enter a file ID');
        return;
    }
    
    try {
        await makeApiCall('DELETE', CONFIG.ENDPOINTS.FILE_DELETE, {
            file_id: fileId
        });
        
        alert('File deleted successfully!');
        refreshFilesList();
        
    } catch (error) {
        alert(`File deletion failed: ${error.message}`);
    }
}

async function handleFileMetadata() {
    const fileId = document.getElementById('file-id-input').value.trim();
    
    if (!fileId) {
        alert('Please enter a file ID');
        return;
    }
    
    try {
        const response = await makeApiCall('GET', CONFIG.ENDPOINTS.FILE_METADATA, null, true, {
            file_id: fileId
        });
        
        alert('File metadata retrieved (check API response log for details)');
        
    } catch (error) {
        alert(`Failed to get file metadata: ${error.message}`);
    }
}

// Sharing handlers
async function handleFileShare(e) {
    e.preventDefault();
    
    const fileId = document.getElementById('share-file-id').value.trim();
    const recipient = document.getElementById('share-recipient').value.trim();
    const expiresAt = document.getElementById('share-expires').value;
    const maxDownloads = document.getElementById('share-max-downloads').value;
    
    if (!fileId || !recipient) {
        alert('Please enter file ID and recipient username');
        return;
    }
    
    const shareData = {
        file_id: fileId,
        recipient_username: recipient,
        encrypted_data_key: 'test-encrypted-key-' + Date.now(),
        share_grant_hmac: 'test-share-hmac-' + Date.now(),
        share_chain_hmac: 'test-chain-hmac-' + Date.now()
    };
    
    if (expiresAt) {
        shareData.expires_at = new Date(expiresAt).toISOString();
    }
    
    if (maxDownloads) {
        shareData.max_downloads = parseInt(maxDownloads);
    }
    
    try {
        const response = await makeApiCall('POST', CONFIG.ENDPOINTS.FILE_SHARE, shareData);
        
        alert('File shared successfully!');
        elements.shareForm.reset();
        
    } catch (error) {
        alert(`File sharing failed: ${error.message}`);
    }
}

async function handleGetFileShares(e) {
    e.preventDefault();
    
    const fileId = document.getElementById('shares-file-id').value.trim();
    
    if (!fileId) {
        alert('Please enter a file ID');
        return;
    }
    
    try {
        const response = await makeApiCall('GET', CONFIG.ENDPOINTS.FILE_SHARES, null, true, { file_id: fileId });
        displaySharesList(response || [], elements.mySharesList);
        
    } catch (error) {
        alert(`Failed to get file shares: ${error.message}`);
    }
}

async function refreshReceivedShares() {
    try {
        const response = await makeApiCall('GET', CONFIG.ENDPOINTS.RECEIVED_SHARES);
        displaySharesList(response || [], elements.receivedSharesList);
    } catch (error) {
        alert(`Failed to refresh received shares: ${error.message}`);
    }
}

function displaySharesList(shares, container) {
    container.innerHTML = '';
    
    if (shares.length === 0) {
        container.innerHTML = '<p>No shares found</p>';
        return;
    }
    
    shares.forEach(share => {
        const shareDiv = document.createElement('div');
        shareDiv.className = 'share-item';
        shareDiv.innerHTML = `
            <strong>Share ID:</strong> ${share.share_id}<br>
            <strong>File ID:</strong> ${share.file_id}<br>
            <strong>Permission:</strong> Read Only<br>
            <strong>Granted:</strong> ${new Date(share.granted_at).toLocaleString()}<br>
            ${share.expires_at ? `<strong>Expires:</strong> ${new Date(share.expires_at).toLocaleString()}<br>` : ''}
            ${share.max_downloads ? `<strong>Max Downloads:</strong> ${share.max_downloads}<br>` : ''}
        `;
        container.appendChild(shareDiv);
    });
}

async function handleRevokeShare(e) {
    e.preventDefault();
    
    const shareId = document.getElementById('revoke-share-id').value.trim();
    
    if (!shareId) {
        alert('Please enter a share ID');
        return;
    }
    
    try {
        await makeApiCall('DELETE', CONFIG.ENDPOINTS.SHARE_REVOKE, null, true, { share_id: shareId });
        
        alert('Share revoked successfully!');
        elements.revokeForm.reset();
        
    } catch (error) {
        alert(`Share revocation failed: ${error.message}`);
    }
}

// Verification handlers
async function handleGetPublicKey(e) {
    e.preventDefault();
    
    const userId = document.getElementById('pubkey-user-id').value.trim();
    
    if (!userId) {
        alert('Please enter a user ID');
        return;
    }
    
    try {
        const response = await makeApiCall('GET', CONFIG.ENDPOINTS.USER_PUBLIC_KEY, null, true, { user_id: userId });
        
        elements.pubkeyResult.innerHTML = `
            <strong>Public Key:</strong><br>
            <pre>${JSON.stringify(response, null, 2)}</pre>
        `;
        
    } catch (error) {
        alert(`Failed to get public key: ${error.message}`);
    }
}

async function handleGenerateVerification(e) {
    e.preventDefault();
    
    const targetUserId = document.getElementById('verify-target-user').value.trim();
    
    if (!targetUserId) {
        alert('Please enter a target user ID');
        return;
    }
    
    try {
        const response = await makeApiCall('POST', CONFIG.ENDPOINTS.VERIFY_GENERATE, {
            target_user_id: targetUserId
        });
        
        elements.verifyCodeResult.innerHTML = `
            <strong>Verification Code Generated:</strong><br>
            <pre>${JSON.stringify(response, null, 2)}</pre>
        `;
        
    } catch (error) {
        alert(`Failed to generate verification code: ${error.message}`);
    }
}

async function handleConfirmVerification(e) {
    e.preventDefault();
    
    const verificationCode = document.getElementById('verify-code-input').value.trim();
    
    if (!verificationCode) {
        alert('Please enter a verification code');
        return;
    }
    
    try {
        const response = await makeApiCall('POST', CONFIG.ENDPOINTS.VERIFY_CONFIRM, {
            verification_code: verificationCode
        });
        
        alert('Verification confirmed successfully!');
        elements.verifyConfirmForm.reset();
        
    } catch (error) {
        alert(`Verification confirmation failed: ${error.message}`);
    }
}

// UI update functions
function updateUI() {
    if (currentUser && sessionToken) {
        // Logged in
        elements.authStatus.textContent = `Logged in as: ${currentUser}`;
        elements.logoutBtn.style.display = 'inline-block';
        elements.fileSection.style.display = 'block';
        elements.sharingSection.style.display = 'block';
        elements.verificationSection.style.display = 'block';
        
        // Load initial data
        refreshFilesList();
        refreshReceivedShares();
    } else {
        // Not logged in
        elements.authStatus.textContent = 'Not logged in';
        elements.logoutBtn.style.display = 'none';
        elements.fileSection.style.display = 'none';
        elements.sharingSection.style.display = 'none';
        elements.verificationSection.style.display = 'none';
    }
}

// Logging functions
function logApiCall(method, url, data) {
    const timestamp = new Date().toISOString();
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    
    logEntry.innerHTML = `
        <div class="timestamp">${timestamp}</div>
        <div><span class="method">${method}</span> <span class="url">${url}</span></div>
        ${data ? `<div>Request: ${JSON.stringify(data, null, 2)}</div>` : ''}
    `;
    
    elements.responseLog.appendChild(logEntry);
    elements.responseLog.scrollTop = elements.responseLog.scrollHeight;
}

function logApiResponse(status, data) {
    const logEntries = elements.responseLog.querySelectorAll('.log-entry');
    const lastEntry = logEntries[logEntries.length - 1];
    
    if (lastEntry) {
        const statusClass = status === 'ERROR' || status >= 400 ? 'status-error' : 'status-success';
        const responseDiv = document.createElement('div');
        responseDiv.innerHTML = `<div class="${statusClass}">Response (${status}): ${JSON.stringify(data, null, 2)}</div>`;
        lastEntry.appendChild(responseDiv);
    }
    
    elements.responseLog.scrollTop = elements.responseLog.scrollHeight;
}

function clearResponseLog() {
    elements.responseLog.innerHTML = '';
} 