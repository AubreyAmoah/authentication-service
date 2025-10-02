# Authentication Service API Documentation

## Overview
This documentation covers all endpoints for the Express.js authentication microservice with role-based access control, organization management, and super admin functionality.

## Base URL
```
http://localhost:3000/api
```

## Authentication
Most endpoints require authentication via JWT token in the Authorization header:
```
Authorization: Bearer <jwt_token>
```

## Response Format
All responses follow this standard format:
```json
{
  "success": 1, // 1 for success, 0 for error
  "message": "Success message",
  "data": {}, // Response data (if applicable)
  "error": "Error message" // Only present on errors
}
```

---

## Public Endpoints

### 1. User Registration
**POST** `/auth/register`

Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123",
  "firstName": "John",
  "lastName": "Doe",
  "organizationId": "org_123" // Optional
}
```

**Response:**
```json
{
  "success": 1,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "organizationId": "org_123",
      "isSuperAdmin": false,
      "isActive": true,
      "createdAt": "2025-09-08T10:00:00Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**Validation Rules:**
- Email: Valid email format, unique
- Password: Minimum 8 characters, at least one uppercase, one lowercase, one number
- FirstName/LastName: Required, 2-50 characters

---

### 2. User Login
**POST** `/auth/login`

Authenticate user and receive tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "organizationId": "org_123",
      "isSuperAdmin": false,
      "roles": ["user", "editor"]
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

---

### 3. Refresh Token
**POST** `/auth/refresh`

Get new access token using refresh token.

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Token refreshed successfully",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

---

### 4. Forgot Password
**POST** `/auth/forgot-password`

Request password reset link.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Password reset link sent to your email"
}
```

---

### 5. Reset Password
**POST** `/auth/reset-password`

Reset password using token from email.

**Request Body:**
```json
{
  "token": "reset_token_123",
  "newPassword": "newSecurePassword123"
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Password reset successfully"
}
```

---

## Protected Endpoints (Require Authentication)

### 6. Get Current User
**GET** `/auth/me`

Get current authenticated user information.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "success": 1,
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "organizationId": "org_123",
      "isSuperAdmin": false,
      "roles": ["user", "editor"],
      "permissions": ["read:posts", "write:posts"],
      "isActive": true,
      "lastLoginAt": "2025-09-08T10:00:00Z"
    }
  }
}
```

---

### 7. Update Password
**PUT** `/auth/password`

Update current user's password.

**Request Body:**
```json
{
  "currentPassword": "currentPassword123",
  "newPassword": "newSecurePassword123"
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Password updated successfully"
}
```

---

### 8. Update Profile
**PUT** `/auth/profile`

Update current user's profile information.

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Smith",
  "phone": "+1234567890",
  "avatar": "https://example.com/avatar.jpg"
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Profile updated successfully",
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Smith",
      "phone": "+1234567890",
      "avatar": "https://example.com/avatar.jpg"
    }
  }
}
```

---

### 9. Logout
**POST** `/auth/logout`

Logout current user and invalidate tokens.

**Response:**
```json
{
  "success": 1,
  "message": "Logged out successfully"
}
```

---

## Role Management Endpoints

### 10. Get User Roles
**GET** `/roles`

Get roles for current user or specific user (admin only).

**Query Parameters:**
- `userId` (optional): Get roles for specific user (admin only)

**Response:**
```json
{
  "success": 1,
  "data": {
    "roles": [
      {
        "id": "role_123",
        "name": "editor",
        "permissions": ["read:posts", "write:posts", "edit:posts"],
        "userId": "user_123",
        "assignedBy": "admin_456",
        "assignedAt": "2025-09-08T10:00:00Z"
      }
    ]
  }
}
```

---

### 11. Assign Role to User
**POST** `/roles`

Assign a role to a user (admin/super admin only).

**Required Roles:** `admin`, `super`

**Request Body:**
```json
{
  "userId": "user_123",
  "role": "editor",
  "permissions": ["read:posts", "write:posts", "edit:posts"]
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Role assigned successfully",
  "data": {
    "role": {
      "id": "role_123",
      "name": "editor",
      "permissions": ["read:posts", "write:posts", "edit:posts"],
      "userId": "user_123"
    }
  }
}
```

---

### 12. Update User Role
**PUT** `/roles/:roleId`

Update permissions for a specific role.

**Required Roles:** `admin`, `super`

**Request Body:**
```json
{
  "permissions": ["read:posts", "write:posts", "edit:posts", "delete:posts"]
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Role updated successfully"
}
```

---

### 13. Remove User Role
**DELETE** `/roles/:roleId`

Remove a role from a user.

**Required Roles:** `admin`, `super`

**Response:**
```json
{
  "success": 1,
  "message": "Role removed successfully"
}
```

---

## User Management Endpoints (Admin/Super Admin)

### 14. Get All Users
**GET** `/users`

Get all users in the organization (admin) or system-wide (super admin).

**Required Roles:** `admin`, `super`

**Query Parameters:**
- `page` (default: 1): Page number
- `limit` (default: 10): Items per page
- `search`: Search by name or email
- `role`: Filter by role
- `isActive`: Filter by active status
- `organizationId`: Filter by organization (super admin only)

**Response:**
```json
{
  "success": 1,
  "data": {
    "users": [
      {
        "id": "user_123",
        "email": "user@example.com",
        "firstName": "John",
        "lastName": "Doe",
        "organizationId": "org_123",
        "isSuperAdmin": false,
        "isActive": true,
        "roles": ["user", "editor"],
        "lastLoginAt": "2025-09-08T10:00:00Z",
        "createdAt": "2025-09-01T10:00:00Z"
      }
    ],
    "pagination": {
      "currentPage": 1,
      "totalPages": 5,
      "totalUsers": 50,
      "limit": 10
    }
  }
}
```

---

### 15. Get User by ID
**GET** `/users/:userId`

Get specific user details.

**Required Roles:** `admin`, `super`

**Response:**
```json
{
  "success": 1,
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "phone": "+1234567890",
      "organizationId": "org_123",
      "isSuperAdmin": false,
      "isActive": true,
      "roles": ["user", "editor"],
      "permissions": ["read:posts", "write:posts"],
      "lastLoginAt": "2025-09-08T10:00:00Z",
      "createdAt": "2025-09-01T10:00:00Z",
      "updatedAt": "2025-09-08T10:00:00Z"
    }
  }
}
```

---

### 16. Create User
**POST** `/users`

Create a new user (admin/super admin only).

**Required Roles:** `admin`, `super`

**Request Body:**
```json
{
  "email": "newuser@example.com",
  "password": "tempPassword123",
  "firstName": "Jane",
  "lastName": "Smith",
  "organizationId": "org_123", // Optional for super admin
  "roles": ["user"], // Optional
  "sendWelcomeEmail": true // Optional, default: true
}
```

**Response:**
```json
{
  "success": 1,
  "message": "User created successfully",
  "data": {
    "user": {
      "id": "user_456",
      "email": "newuser@example.com",
      "firstName": "Jane",
      "lastName": "Smith",
      "organizationId": "org_123",
      "isActive": true,
      "roles": ["user"]
    }
  }
}
```

---

### 17. Update User
**PUT** `/users/:userId`

Update user information.

**Required Roles:** `admin`, `super`

**Request Body:**
```json
{
  "firstName": "Jane",
  "lastName": "Doe",
  "phone": "+1234567890",
  "isActive": true,
  "organizationId": "org_456" // Super admin only
}
```

**Response:**
```json
{
  "success": 1,
  "message": "User updated successfully",
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "firstName": "Jane",
      "lastName": "Doe",
      "phone": "+1234567890",
      "isActive": true
    }
  }
}
```

---

### 18. Deactivate User
**PUT** `/users/:userId/deactivate`

Deactivate a user account.

**Required Roles:** `admin`, `super`

**Response:**
```json
{
  "success": 1,
  "message": "User deactivated successfully"
}
```

---

### 19. Activate User
**PUT** `/users/:userId/activate`

Activate a user account.

**Required Roles:** `admin`, `super`

**Response:**
```json
{
  "success": 1,
  "message": "User activated successfully"
}
```

---

### 20. Delete User
**DELETE** `/users/:userId`

Permanently delete a user (super admin only).

**Required Roles:** `super`

**Response:**
```json
{
  "success": 1,
  "message": "User deleted successfully"
}
```

---

## Organization Management Endpoints

### 21. Get All Organizations
**GET** `/organizations`

Get all organizations (super admin only).

**Required Roles:** `super`

**Query Parameters:**
- `page` (default: 1): Page number
- `limit` (default: 10): Items per page
- `search`: Search by organization name
- `isActive`: Filter by active status

**Response:**
```json
{
  "success": 1,
  "data": {
    "organizations": [
      {
        "id": "org_123",
        "name": "Tech Corp",
        "description": "Technology company",
        "domain": "techcorp.com",
        "isActive": true,
        "settings": {
          "allowRegistration": true,
          "requireEmailVerification": true
        },
        "userCount": 25,
        "adminCount": 3,
        "createdAt": "2025-09-01T10:00:00Z"
      }
    ],
    "pagination": {
      "currentPage": 1,
      "totalPages": 3,
      "totalOrganizations": 25,
      "limit": 10
    }
  }
}
```

---

### 22. Get Organization
**GET** `/organizations/:organizationId`

Get specific organization details.

**Required Roles:** `admin` (own org), `super` (any org)

**Response:**
```json
{
  "success": 1,
  "data": {
    "organization": {
      "id": "org_123",
      "name": "Tech Corp",
      "description": "Technology company",
      "domain": "techcorp.com",
      "logo": "https://example.com/logo.png",
      "isActive": true,
      "settings": {
        "allowRegistration": true,
        "requireEmailVerification": true,
        "passwordPolicy": {
          "minLength": 8,
          "requireUppercase": true,
          "requireLowercase": true,
          "requireNumbers": true,
          "requireSymbols": false
        }
      },
      "stats": {
        "totalUsers": 25,
        "activeUsers": 23,
        "adminUsers": 3,
        "lastActivityAt": "2025-09-08T10:00:00Z"
      },
      "createdAt": "2025-09-01T10:00:00Z",
      "updatedAt": "2025-09-08T10:00:00Z"
    }
  }
}
```

---

### 23. Create Organization
**POST** `/organizations`

Create a new organization (super admin only).

**Required Roles:** `super`

**Request Body:**
```json
{
  "name": "New Corp",
  "description": "A new organization",
  "domain": "newcorp.com",
  "adminEmail": "admin@newcorp.com",
  "settings": {
    "allowRegistration": true,
    "requireEmailVerification": true
  }
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Organization created successfully",
  "data": {
    "organization": {
      "id": "org_456",
      "name": "New Corp",
      "description": "A new organization",
      "domain": "newcorp.com",
      "isActive": true,
      "adminUser": {
        "id": "user_789",
        "email": "admin@newcorp.com"
      }
    }
  }
}
```

---

### 24. Update Organization
**PUT** `/organizations/:organizationId`

Update organization information.

**Required Roles:** `admin` (own org), `super` (any org)

**Request Body:**
```json
{
  "name": "Updated Corp Name",
  "description": "Updated description",
  "logo": "https://example.com/new-logo.png",
  "settings": {
    "allowRegistration": false,
    "requireEmailVerification": true
  }
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Organization updated successfully"
}
```

---

### 25. Delete Organization
**DELETE** `/organizations/:organizationId`

Delete an organization and all its users (super admin only).

**Required Roles:** `super`

**Response:**
```json
{
  "success": 1,
  "message": "Organization deleted successfully"
}
```

---

## Super Admin Endpoints

### 26. Get System Statistics
**GET** `/super-admin/stats`

Get system-wide statistics.

**Required Roles:** `super`

**Response:**
```json
{
  "success": 1,
  "data": {
    "stats": {
      "totalUsers": 1250,
      "activeUsers": 1180,
      "totalOrganizations": 45,
      "activeOrganizations": 42,
      "superAdmins": 3,
      "totalLogins": 15620,
      "todayLogins": 245,
      "systemHealth": {
        "status": "healthy",
        "uptime": "15 days, 4 hours",
        "memoryUsage": "65%",
        "cpuUsage": "23%"
      },
      "recentActivity": [
        {
          "type": "user_registration",
          "count": 12,
          "timeframe": "last_24h"
        },
        {
          "type": "organization_created",
          "count": 2,
          "timeframe": "last_7d"
        }
      ]
    }
  }
}
```

---

### 27. Get All Super Admins
**GET** `/super-admin/admins`

Get all super admin users.

**Required Roles:** `super`

**Response:**
```json
{
  "success": 1,
  "data": {
    "superAdmins": [
      {
        "id": "user_001",
        "email": "superadmin@system.com",
        "firstName": "System",
        "lastName": "Administrator",
        "isActive": true,
        "lastLoginAt": "2025-09-08T10:00:00Z",
        "createdAt": "2025-09-01T10:00:00Z"
      }
    ]
  }
}
```

---

### 28. Grant Super Admin
**POST** `/super-admin/grant`

Grant super admin privileges to a user.

**Required Roles:** `super`

**Request Body:**
```json
{
  "userId": "user_123"
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Super admin privileges granted successfully"
}
```

---

### 29. Revoke Super Admin
**POST** `/super-admin/revoke`

Revoke super admin privileges from a user.

**Required Roles:** `super`

**Request Body:**
```json
{
  "userId": "user_123"
}
```

**Response:**
```json
{
  "success": 1,
  "message": "Super admin privileges revoked successfully"
}
```

---

### 30. System Logs
**GET** `/super-admin/logs`

Get system activity logs.

**Required Roles:** `super`

**Query Parameters:**
- `page` (default: 1): Page number
- `limit` (default: 50): Items per page
- `level`: Log level (info, warn, error)
- `startDate`: Start date for logs
- `endDate`: End date for logs
- `userId`: Filter by user ID
- `action`: Filter by action type

**Response:**
```json
{
  "success": 1,
  "data": {
    "logs": [
      {
        "id": "log_123",
        "level": "info",
        "action": "user_login",
        "userId": "user_123",
        "userEmail": "user@example.com",
        "organizationId": "org_123",
        "ipAddress": "192.168.1.100",
        "userAgent": "Mozilla/5.0...",
        "details": {
          "loginMethod": "email_password",
          "success": true
        },
        "timestamp": "2025-09-08T10:00:00Z"
      }
    ],
    "pagination": {
      "currentPage": 1,
      "totalPages": 100,
      "totalLogs": 5000,
      "limit": 50
    }
  }
}
```

---

## Error Responses

### Common Error Codes

**400 - Bad Request**
```json
{
  "success": 0,
  "message": "Validation failed",
  "errors": [
    {
      "field": "email",
      "message": "Invalid email format"
    },
    {
      "field": "password",
      "message": "Password must be at least 8 characters"
    }
  ]
}
```

**401 - Unauthorized**
```json
{
  "success": 0,
  "message": "Authentication required"
}
```

**403 - Forbidden**
```json
{
  "success": 0,
  "message": "Insufficient permissions"
}
```

**404 - Not Found**
```json
{
  "success": 0,
  "message": "User not found"
}
```

**409 - Conflict**
```json
{
  "success": 0,
  "message": "Email already exists"
}
```

**429 - Too Many Requests**
```json
{
  "success": 0,
  "message": "Rate limit exceeded. Try again in 15 minutes"
}
```

**500 - Internal Server Error**
```json
{
  "success": 0,
  "message": "Internal server error"
}
```

---

## Rate Limiting

All endpoints are rate-limited to prevent abuse:

- **Authentication endpoints**: 5 requests per minute per IP
- **User management endpoints**: 100 requests per hour per user
- **Super admin endpoints**: 200 requests per hour per user

When rate limit is exceeded, the API returns a 429 status code with retry information in headers:
```
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1694168400
Retry-After: 60
```

---

## Webhooks (Optional)

The system can send webhooks for certain events:

### User Events
- `user.created`
- `user.updated`
- `user.deleted`
- `user.login`
- `user.logout`

### Organization Events
- `organization.created`
- `organization.updated`
- `organization.deleted`

### Role Events
- `role.assigned`
- `role.updated`
- `role.removed`

### Webhook Payload Example
```json
{
  "event": "user.created",
  "timestamp": "2025-09-08T10:00:00Z",
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "organizationId": "org_123"
    }
  }
}
```

---

## SDKs and Integration

### JavaScript/Node.js Example
```javascript
const axios = require('axios');

class AuthService {
  constructor(baseURL, apiKey) {
    this.client = axios.create({
      baseURL,
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      }
    });
  }

  async login(email, password) {
    const response = await this.client.post('/auth/login', {
      email,
      password
    });
    return response.data;
  }

  async getCurrentUser() {
    const response = await this.client.get('/auth/me');
    return response.data;
  }

  async createUser(userData) {
    const response = await this.client.post('/users', userData);
    return response.data;
  }
}
```

### cURL Examples

**Login:**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'
```

**Get Current User:**
```bash
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Create User (Admin):**
```bash
curl -X POST http://localhost:3000/api/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"newuser@example.com","password":"password123","firstName":"John","lastName":"Doe"}'
```

---

## Testing

Use the provided endpoints for testing:

1. **Health Check**: `GET /health` - Check if service is running
2. **API Version**: `GET /version` - Get API version information

---


# Audit Logs Export API Documentation

## Overview
The Audit Logs Export API allows administrators to export audit log data in multiple formats (CSV and Excel) for reporting, compliance, and analysis purposes.

---

## Endpoint

### Export Audit Logs
**GET** `/api/audit-logs/export`

Exports all audit logs in the specified format.

---

## Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `format` | string | No | `csv` | Export format. Accepted values: `csv`, `excel` |

---

## Request Examples

### Export as CSV (Default)
```http


# Login Attempts API Documentation

## Overview
The Login Attempts API provides comprehensive endpoints for tracking, monitoring, and analyzing user login activity. This system helps administrators maintain security by monitoring access patterns, detecting suspicious activities, and maintaining audit trails.

---

## Table of Contents
- [Authentication](#authentication)
- [Endpoints](#endpoints)
  - [Get All Login Attempts](#get-all-login-attempts)
  - [Get Filtered Login Attempts](#get-filtered-login-attempts)
  - [Get User Login Attempts](#get-user-login-attempts)
  - [Get Recent Login Attempts](#get-recent-login-attempts)
  - [Get Login Attempts by IP](#get-login-attempts-by-ip)
  - [Get Login Attempts Statistics](#get-login-attempts-statistics)
  - [Export Login Attempts](#export-login-attempts)
  - [Cleanup Old Login Attempts](#cleanup-old-login-attempts)
- [Data Models](#data-models)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Best Practices](#best-practices)

---

## Authentication

All endpoints require authentication via JWT token in the Authorization header:
```http

upda
This documentation covers all endpoints in your Express authentication microservice with comprehensive request/response examples, error handling, and usage guidelines.