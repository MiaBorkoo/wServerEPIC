# wServerEPIC
<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.12+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115.12-009688.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Latest-336791.svg)

</div>

## 📋 Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Security Architecture](#security-architecture)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Usage](#usage)
  - [Running the Server](#running-the-server)
  - [API Documentation](#api-documentation)
- [Development](#development)
  - [Project Structure](#project-structure)
  - [Testing](#testing)
  - [Code Style](#code-style)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## 🔍 Overview

wServerEPIC is an enterprise-grade, high-security file sharing platform implementing zero-knowledge architecture. Built with a focus on security-first design, it provides end-to-end encrypted file sharing capabilities while ensuring the server remains an untrusted component in the security model.

The platform is designed for organizations requiring the highest levels of data protection while maintaining ease of use and seamless file sharing capabilities.

## ⭐ Key Features

### Security
- **Zero-Knowledge Architecture**: Server operates without access to plaintext data
- **End-to-End Encryption**: Client-side encryption of all files and metadata
- **Two-Factor Authentication**: TOTP-based 2FA implementation
- **Granular Access Control**: Role-based access control with multiple permission levels
- **Audit Logging**: Comprehensive activity tracking and security event logging

### File Sharing
- **Secure File Transfer**: Envelope encryption for secure file sharing
- **Time-Limited Access**: Configurable expiring share links
- **Team Management**: Collaborative workspace with team-based permissions
- **Storage Quotas**: Configurable team-based storage limits (2GiB default)
- **File Versioning**: Track and restore previous versions of files

### Performance
- **Async Operations**: Built on FastAPI for high-performance async processing
- **Scalable Architecture**: Designed for horizontal scaling
- **Efficient Caching**: Redis-based caching for improved performance
- **Chunked Uploads**: Support for large file uploads with resume capability

## 🔒 Security Architecture

### Zero-Knowledge Design
1. All encryption/decryption occurs client-side
2. Server stores only encrypted data and metadata
3. Key management handled through envelope encryption
4. Perfect forward secrecy through rotating keys

### Encryption Standards
- AES-256-GCM for file encryption
- RSA-4096 for key exchange
- Argon2id for password hashing
- Ed25519 for digital signatures

## 🛠 Technology Stack

### Backend
- **Framework**: FastAPI 0.115.12
- **Database**: PostgreSQL with SQLAlchemy 2.0.36
- **Cache**: Redis 6.x
- **Server**: Uvicorn (ASGI)
- **Authentication**: JWT + TOTP

### Security
- **Cryptography**: Industry-standard libraries
- **Password Hashing**: Argon2id
- **Session Management**: JWT with secure cookie handling
- **2FA**: TOTP (RFC 6238 compliant)

### Tools
- **Migration**: Alembic
- **Testing**: pytest
- **Documentation**: OpenAPI (Swagger)
- **Monitoring**: Prometheus + Grafana

## 🚀 Getting Started

### Prerequisites

Required software:
```bash
- Python 3.12 or higher
- PostgreSQL 13+
- Redis 6+
- OpenSSL
```

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/wServerEPIC.git
cd wServerEPIC
```

2. Set up virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Generate SSL certificates:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

5. Configure environment:
```bash
cp .env.example .env
# Edit .env with your configuration
```

6. Initialize database:
```bash
alembic upgrade head
```

### Configuration

Essential environment variables:
```bash
DATABASE_URL=postgresql://user:password@localhost/dbname
REDIS_URL=redis://localhost:6379
SECRET_KEY=your-secret-key
STORAGE_PATH=/path/to/storage
MAX_UPLOAD_SIZE=104857600  # 100MB
TEAM_QUOTA_BYTES=2147483648  # 2GB
```

## 📖 Usage

### Running the Server

Development mode:
```bash
uvicorn app.main:app --reload --ssl-keyfile=key.pem --ssl-certfile=cert.pem
```

Production mode:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 443 \
  --ssl-keyfile=key.pem \
  --ssl-certfile=cert.pem \
  --workers 4 \
  --proxy-headers
```

### API Documentation

- **Swagger UI**: `https://localhost:8000/docs`
- **ReDoc**: `https://localhost:8000/redoc`

## 💻 Development

### Project Structure
```
wServerEPIC/
├── alembic/                # Database migrations
├── app/
│   ├── core/              # Core functionality
│   │   ├── config.py      # Configuration
│   │   ├── security.py    # Security utilities
│   │   └── exceptions.py  # Custom exceptions
│   ├── db/                # Database models
│   ├── routers/           # API endpoints
│   ├── schemas/           # Pydantic models
│   ├── services/          # Business logic
│   └── test/             # Unit tests
├── scripts/               # Utility scripts
└── tests/                # Integration tests
```

### Testing

Run test suite:
```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=app tests/ --cov-report=html

# Run specific test category
pytest tests/security/
```

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Document all public APIs
- Maintain test coverage > 80%

## 🛡️ Security Considerations

1. **Data Protection**
   - All sensitive data must be encrypted client-side
   - Use secure random number generation
   - Implement rate limiting
   - Regular security audits

2. **Operational Security**
   - Monitor audit logs
   - Regular dependency updates
   - Backup encryption keys securely
   - Implement incident response plan

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

For support and queries:
- Open an issue
- Contact: support@wserverepic.com
- Documentation: [https://docs.wserverepic.com](https://docs.wserverepic.com)

---

<div align="center">
Made with ❤️ by the ChrisPP Team
</div>
