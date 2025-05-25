// Configuration for the test frontend
const CONFIG = {
    // Change this to match your FastAPI server URL
    API_BASE_URL: 'http://localhost:8000',
    
    // Default values
    DEFAULT_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',  // Base32 encoded secret for testing
    
    // API endpoints based on the requirements doc
    ENDPOINTS: {
        // Authentication endpoints
        SALTS: '/api/user/{username}/salts',
        REGISTER: '/api/auth/register',
        LOGIN: '/api/auth/login',
        TOTP: '/api/auth/totp',
        LOGOUT: '/api/auth/logout',
        CHANGE_PASSWORD: '/api/user/change_password',
        
        // File management endpoints
        FILES_LIST: '/api/files',
        FILE_UPLOAD: '/api/files/upload',
        FILE_DOWNLOAD: '/api/files/download',
        FILE_DELETE: '/api/files/delete',
        FILE_METADATA: '/api/files/metadata',
        
        // Sharing endpoints
        FILE_SHARE: '/api/files/share',
        SHARE_REVOKE: '/api/files/share/{share_id}',
        FILE_SHARES: '/api/files/shares',
        RECEIVED_SHARES: '/api/files/shares/received',
        
        // Verification endpoints
        USER_PUBLIC_KEY: '/api/users/{user_id}/public_key',
        VERIFY_GENERATE: '/api/verify/generate',
        VERIFY_CONFIRM: '/api/verify/confirm'
    }
};

// Helper function to build full API URLs
function getApiUrl(endpoint, params = {}) {
    let url = CONFIG.API_BASE_URL + endpoint;
    
    // Replace path parameters
    for (const [key, value] of Object.entries(params)) {
        url = url.replace(`{${key}}`, encodeURIComponent(value));
    }
    
    return url;
} 