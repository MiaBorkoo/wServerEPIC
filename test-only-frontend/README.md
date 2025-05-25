# Secure File Share - Test Frontend

This is a simple JavaScript web application designed to test all the functionality of the FastAPI secure file sharing server described in the Project Requirements Document.

## Features

This test frontend demonstrates all the API endpoints from the requirements:

### Authentication
- User registration with TOTP setup
- Two-factor login (password + TOTP)
- Password change with TOTP verification
- Session management and logout

### File Management
- File upload with encryption metadata
- List user's files
- Download files
- Delete files
- Get file metadata

### File Sharing
- Share files with other users
- List file shares
- View received shares
- Revoke shares
- Support for permission levels (read, write, admin)
- Time-limited shares
- Download limits

### Verification
- Get user public keys
- Generate verification codes
- Confirm verification codes (TOFU implementation)

## Setup

1. **Configure the API URL**: Edit `config.js` and change `API_BASE_URL` to match your FastAPI server:
   ```javascript
   API_BASE_URL: 'http://localhost:8000',  // Change this to your server URL
   ```

2. **Serve the files**: You can use any web server. For example:
   ```bash
   # Using Python's built-in server
   cd test-only-frontend
   python3 -m http.server 8080
   
   # Or using Node.js http-server
   npx http-server -p 8080
   
   # Or using PHP
   php -S localhost:8080
   ```

3. **Open in browser**: Navigate to `http://localhost:8080`

## Usage

### Getting Started

1. **Register a new user**:
   - Fill in username and password
   - Optionally provide a TOTP secret (uses default if empty)
   - Click "Register"

2. **Login**:
   - Enter username and password, click "Login (Step 1)"
   - Enter TOTP code, click "Verify TOTP (Step 2)"
   - The interface will show file management options after successful login

3. **Upload and manage files**:
   - Use the file upload section to upload files
   - View your files in the "My Files" section
   - Use file operations with the File ID from your files list

4. **Share files**:
   - Copy a File ID from your files list
   - Enter recipient username and permission level
   - Optionally set expiration time and download limits

5. **View API calls**: All API requests and responses are logged in the "API Response Log" section at the bottom

### Testing Tips

- **TOTP codes**: The default TOTP secret `JBSWY3DPEHPK3PXP` can be used with any TOTP app like Google Authenticator or Authy
- **File IDs**: Copy File IDs from the "My Files" list to use in other operations
- **Share IDs**: Copy Share IDs from the shares lists to revoke shares
- **API logging**: Watch the response log to see exactly what data is being sent/received

## Security Notes

⚠️ **This is a testing-only frontend!** It doesn't implement real encryption:

- Passwords are sent in plaintext (the real server should hash them client-side)
- Files are uploaded without encryption (real implementation would encrypt client-side)
- HMAC values are fake/test values (but user_data_hmac is computed client-side for integrity)
- No real cryptographic operations are performed

This frontend is designed to:
- Test server API endpoints
- Validate request/response formats
- Demonstrate the complete workflow
- Help debug server implementation

**Note**: The registration endpoint now includes `user_data_hmac` computed client-side from all user registration data for integrity protection, following the zero-knowledge principle where the server doesn't perform cryptographic operations.

## File Structure

```
test-only-frontend/
├── index.html          # Main HTML structure
├── style.css           # CSS styling
├── config.js           # Configuration and API endpoints
├── app.js              # Main application logic
└── README.md           # This file
```

## API Endpoints Tested

All endpoints from the requirements document are implemented:

- `GET /api/user/{username}/salts`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/totp`
- `POST /api/auth/logout`
- `POST /api/user/change_password`
- `GET /api/files`
- `POST /api/files/upload`
- `POST /api/files/download`
- `DELETE /api/files/delete`
- `POST /api/files/metadata`
- `POST /api/files/share`
- `DELETE /api/files/share/{share_id}`
- `GET /api/files/shares`
- `GET /api/shares/received`
- `GET /api/users/{user_id}/public_key`
- `POST /api/verify/generate`
- `POST /api/verify/confirm`

## Browser Compatibility

This frontend uses modern JavaScript features:
- ES6+ syntax (arrow functions, async/await, etc.)
- Fetch API
- FormData for file uploads

Supported browsers:
- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+ 