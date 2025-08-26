# Authentication Microservice

A comprehensive, production-ready authentication microservice built with Node.js, Express, PostgreSQL, Prisma, and JWT. This service provides secure authentication, user management, role-based access control, and OAuth integration that can be seamlessly integrated into any application or microservice architecture.

## 🚀 Features

### Core Authentication
- **User Registration & Login** - Secure account creation and authentication
- **JWT Token Management** - Access and refresh token implementation
- **Password Security** - Bcrypt hashing with configurable rounds
- **Email Verification** - Account verification via email links
- **Password Reset** - Secure password reset via email tokens
- **Session Management** - Multi-device session tracking and management

### Organization Management
- **Multi-tenant Architecture** - Organization-based user segregation
- **Organization Settings** - Customizable organization configurations
- **Organization Statistics** - User and activity analytics

### Role-Based Access Control (RBAC)
- **Dynamic Roles** - Create and manage custom roles
- **Granular Permissions** - Fine-grained permission system
- **Role Assignment** - Assign multiple roles to users
- **Permission Checking** - Middleware for permission validation

### OAuth 2.0 Integration
- **Google OAuth** - Sign in with Google
- **GitHub OAuth** - Sign in with GitHub
- **Provider Linking** - Link multiple OAuth providers to one account
- **Account Unlinking** - Remove OAuth provider connections

### Multi-Factor Authentication (MFA)
- **TOTP Support** - Time-based One-Time Passwords (Google Authenticator, Authy)
- **QR Code Generation** - Easy setup with authenticator apps
- **Backup Codes** - Recovery codes for account access
- **MFA Middleware** - Protect sensitive endpoints
- **Login Integration** - Seamless MFA verification during login

### User Management
- **User Profiles** - Comprehensive user profile management
- **User Invitations** - Invite users to organizations
- **User Activation/Deactivation** - Account status management
- **User Search** - Search and filter users

### Security Features
- **Rate Limiting** - Protect against brute force attacks
- **CORS Protection** - Cross-origin request security
- **Helmet Integration** - Security headers
- **Input Validation** - Joi-based request validation
- **SQL Injection Protection** - Prisma ORM protection

## 📁 Project Structure

```
authentication-service/
├── config/                 # Configuration files
│   └── index.js            # Main configuration
├── controllers/            # Request handlers
│   ├── authController.js   # Authentication endpoints
│   ├── userController.js   # User management
│   ├── organizationController.js # Organization management
│   └── roleController.js   # Role management
├── middleware/             # Express middleware
│   ├── auth.js             # Authentication middleware
│   └── errorHandler.js     # Error handling
├── models/                 # Database models (Prisma)
├── plugins/                # Feature plugins
│   └── oauth.js            # OAuth 2.0 implementation
├── routes/                 # API routes
│   ├── auth.js             # Authentication routes
│   ├── users.js            # User routes
│   ├── organizations.js    # Organization routes
│   ├── roles.js            # Role routes
│   └── oauth.js            # OAuth routes
├── scripts/                # Utility scripts
│   └── seed.js             # Database seeding
├── services/               # Business logic
│   ├── authService.js      # Authentication logic
│   ├── userService.js      # User management logic
│   ├── organizationService.js # Organization logic
│   └── roleService.js      # Role management logic
├── utils/                  # Utility functions
│   ├── database.js         # Database connection
│   ├── email.js            # Email service
│   ├── hash.js             # Password hashing
│   ├── jwt.js              # JWT utilities
│   ├── response.js         # Response helpers
│   └── validation.js       # Input validation schemas
├── prisma/                 # Database schema and migrations
│   └── schema.prisma       # Database schema
├── .env.example            # Environment variables template
├── package.json            # Dependencies and scripts
└── index.js                # Application entry point
```

## 🛠️ Installation & Setup

### Prerequisites
- Node.js (v16 or higher)
- PostgreSQL (v12 or higher)
- npm or yarn

### 1. Clone the Repository
```bash
git clone <repository-url>
cd authentication-service
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Environment Configuration
Copy the example environment file and configure your settings:
```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```env
# Database
DATABASE_URL="postgresql://username:password@localhost:5432/auth_service_db"

# JWT Secrets
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_REFRESH_SECRET=your-refresh-token-secret

# Email Configuration (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# OAuth Providers (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

### 4. Database Setup
```bash
# Generate Prisma client
npm run generate

# Run database migrations
npm run migrate

# Seed database with demo data (optional)
npm run seed
```

### 5. Start the Service
```bash
# Development mode
npm run dev

# Production mode
npm start
```

The service will be available at `http://localhost:3000`

## 📚 API Documentation

### Authentication Endpoints

#### Register
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "organizationName": "My Company" // optional
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "organizationSlug": "my-company" // optional
}
```

#### Refresh Token
```http
POST /api/auth/refresh-token
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### Get Profile
```http
GET /api/auth/profile
Authorization: Bearer your-access-token
```

### User Management Endpoints

#### Get Users
```http
GET /api/users?page=1&limit=10&search=john
Authorization: Bearer your-access-token
```

#### Update User
```http
PATCH /api/users/:id
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Smith"
}
```

#### Assign Role
```http
POST /api/users/:id/roles
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "roleId": "role-uuid"
}
```

### Organization Endpoints

#### Get Current Organization
```http
GET /api/organizations/current
Authorization: Bearer your-access-token
```

#### Update Organization
```http
PATCH /api/organizations/current
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "name": "Updated Company Name",
  "website": "https://newwebsite.com"
}
```

### Role Management Endpoints

#### Get Roles
```http
GET /api/roles
Authorization: Bearer your-access-token
```

#### Create Role
```http
POST /api/roles
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "name": "Manager",
  "description": "Team management role",
  "permissions": ["users.read", "users.update"]
}
```

### OAuth Endpoints

#### Google OAuth
```http
GET /api/oauth/google?returnUrl=http://localhost:3001/dashboard
```

#### GitHub OAuth
```http
GET /api/oauth/github?returnUrl=http://localhost:3001/dashboard
```

### Multi-Factor Authentication Endpoints

#### Get MFA Status
```http
GET /api/mfa/status
Authorization: Bearer your-access-token
```

#### Start MFA Setup
```http
POST /api/mfa/setup/start
Authorization: Bearer your-access-token
```

#### Complete MFA Setup
```http
POST /api/mfa/setup/complete
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "token": "123456"
}
```

#### Verify MFA Token
```http
POST /api/mfa/verify
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "token": "123456",
  "isBackupCode": false
}
```

#### Disable MFA
```http
POST /api/mfa/disable
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "password": "current-password",
  "token": "123456"
}
```

#### Regenerate Backup Codes
```http
POST /api/mfa/backup-codes/regenerate
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "password": "current-password"
}
```

#### Login with MFA
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password",
  "mfaToken": "123456",
  "isBackupCode": false
}
```

## 🔐 Multi-Factor Authentication (MFA) Guide

### Setting Up MFA

1. **Start MFA Setup**
   ```javascript
   const response = await fetch('/api/mfa/setup/start', {
     method: 'POST',
     headers: { 'Authorization': `Bearer ${token}` }
   });
   const { setup } = await response.json();
   ```

2. **Display QR Code**
   ```html
   <img src="${setup.qrCode}" alt="MFA QR Code" />
   <p>Manual entry code: ${setup.manualEntryCode}</p>
   ```

3. **Complete Setup**
   ```javascript
   const response = await fetch('/api/mfa/setup/complete', {
     method: 'POST',
     headers: {
       'Authorization': `Bearer ${token}`,
       'Content-Type': 'application/json'
     },
     body: JSON.stringify({ token: userEnteredCode })
   });
   ```

### MFA Login Flow

```javascript
// Step 1: Login with credentials
const loginResponse = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password })
});

const loginData = await loginResponse.json();

if (loginData.mfaRequired) {
  // Step 2: Prompt for MFA token
  const mfaToken = prompt('Enter your 6-digit MFA code:');
  
  // Step 3: Login with MFA token
  const mfaResponse = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      email, 
      password, 
      mfaToken 
    })
  });
  
  const mfaData = await mfaResponse.json();
  // Login successful
}
```

### Using MFA Middleware

Protect sensitive endpoints with MFA verification:

```javascript
const { requireMFAVerification } = require('./plugins/mfa');

// Require MFA for sensitive operations
router.delete('/api/users/:id', 
  authenticate, 
  requireMFAVerification, 
  deleteUserController
);
```

### Backup Codes

- Generated during MFA setup
- 10 single-use recovery codes
- Store securely (download, print, or save in password manager)
- Can regenerate new codes anytime
- Use when authenticator app is unavailable

## 🔐 Permission System

The service includes a comprehensive permission system:

### Available Permissions
- **User Management**: `users.create`, `users.read`, `users.update`, `users.delete`, `users.invite`
- **Role Management**: `roles.create`, `roles.read`, `roles.update`, `roles.delete`, `roles.assign`
- **Organization**: `organization.read`, `organization.update`, `organization.settings`
- **Sessions**: `sessions.read`, `sessions.revoke`
- **API Keys**: `api-keys.create`, `api-keys.read`, `api-keys.delete`
- **Invitations**: `invitations.send`, `invitations.read`, `invitations.revoke`

### Using Permissions in Middleware
```javascript
const { requirePermission } = require('./middleware/auth');

// Require specific permission
router.get('/users', requirePermission('users.read'), getUsersController);

// Require any of multiple permissions
router.get('/dashboard', requireAnyPermission(['users.read', 'organization.read']), getDashboard);
```

## 🔌 Integration Examples

### React Frontend Integration
```javascript
// Login function
const login = async (email, password) => {
  const response = await fetch('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });
  
  const data = await response.json();
  
  if (data.success) {
    localStorage.setItem('accessToken', data.data.tokens.accessToken);
    localStorage.setItem('refreshToken', data.data.tokens.refreshToken);
    return data.data.user;
  }
  
  throw new Error(data.message);
};

// Authenticated API call
const fetchUserProfile = async () => {
  const token = localStorage.getItem('accessToken');
  
  const response = await fetch('http://localhost:3000/api/auth/profile', {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });
  
  return response.json();
};
```

### Express.js Backend Integration
```javascript
const axios = require('axios');

// Middleware to verify tokens with auth service
const verifyToken = async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  try {
    const response = await axios.get('http://localhost:3000/api/auth/check', {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    req.user = response.data.data.user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};
```

## 🧪 Testing

### Demo Accounts
After running the seed script, you can use these demo accounts:

1. **Admin User**
   - Email: `admin@democompany.com`
   - Password: `Admin123!`
   - Role: Admin (full access)

2. **Member User**
   - Email: `user@democompany.com`
   - Password: `Admin123!`
   - Role: Member (standard access)

3. **Viewer User**
   - Email: `viewer@democompany.com`
   - Password: `Admin123!`
   - Role: Viewer (read-only access)

### API Testing with cURL
```bash
# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@democompany.com","password":"Admin123!"}'

# Get profile (replace TOKEN with actual token)
curl -X GET http://localhost:3000/api/auth/profile \
  -H "Authorization: Bearer TOKEN"
```

## 🚀 Deployment

### Environment Variables for Production
```env
NODE_ENV=production
PORT=3000
DATABASE_URL=postgresql://user:pass@host:5432/db
JWT_SECRET=production-secret-key
CORS_ORIGIN=https://yourdomain.com
```

### Docker Deployment
```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npx prisma generate

EXPOSE 3000
CMD ["npm", "start"]
```

### Health Check
The service provides a health check endpoint:
```http
GET /health
```

## 🔧 Configuration Options

### JWT Configuration
- `JWT_SECRET`: Secret key for signing access tokens
- `JWT_EXPIRES_IN`: Access token expiration time (default: 7d)
- `JWT_REFRESH_SECRET`: Secret key for refresh tokens
- `JWT_REFRESH_EXPIRES_IN`: Refresh token expiration (default: 30d)

### Security Configuration
- `BCRYPT_ROUNDS`: Password hashing rounds (default: 12)
- `RATE_LIMIT_WINDOW_MS`: Rate limiting window (default: 15 minutes)
- `RATE_LIMIT_MAX_REQUESTS`: Max requests per window (default: 100)

### Email Configuration
- `SMTP_HOST`: Email server host
- `SMTP_PORT`: Email server port
- `SMTP_USER`: Email username
- `SMTP_PASSWORD`: Email password

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin feature/new-feature`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the API documentation at `/api/docs`
- Review the health check at `/health`

## 🎯 Roadmap

- [ ] Two-factor authentication (2FA)
- [ ] API key management
- [ ] Audit logging
- [ ] WebSocket support for real-time updates
- [ ] Single Sign-On (SSO) integration
- [ ] Account lockout policies
- [ ] Password policy enforcement
- [ ] Social media OAuth providers (Twitter, LinkedIn)
- [ ] Mobile app SDK