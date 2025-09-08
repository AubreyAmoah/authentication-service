# Authentication Service Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Database Setup](#database-setup)
4. [Local Development](#local-development)
5. [Production Deployment](#production-deployment)
   - [Docker Deployment](#docker-deployment)
   - [Cloud Deployment (AWS)](#cloud-deployment-aws)
   - [Cloud Deployment (Google Cloud)](#cloud-deployment-google-cloud)
   - [Cloud Deployment (Azure)](#cloud-deployment-azure)
   - [VPS/Traditional Server](#vpstraditional-server)
6. [Monitoring and Logging](#monitoring-and-logging)
7. [Security Considerations](#security-considerations)
8. [Backup and Recovery](#backup-and-recovery)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements
- **Node.js**: v18.x or higher
- **npm**: v9.x or higher (or yarn v1.22+)
- **PostgreSQL**: v13.x or higher
- **Redis**: v6.x or higher (for session storage and caching)
- **Git**: Latest version

### Development Tools
- **Docker**: v20.x or higher (optional but recommended)
- **Docker Compose**: v2.x or higher
- **PM2**: For process management in production

---

## Environment Setup

### 1. Clone the Repository
```bash
git clone https://github.com/your-org/authentication-service.git
cd authentication-service
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Environment Configuration
Create environment files for different stages:

#### `.env.development`
```bash
# Database
DATABASE_URL="postgresql://auth_user:auth_password@localhost:5432/auth_dev"

# JWT Configuration
JWT_SECRET="dev-jwt-secret-change-in-production"
JWT_REFRESH_SECRET="dev-refresh-secret-change-in-production"
ACCESS_TOKEN_EXPIRY="15m"
REFRESH_TOKEN_EXPIRY="7d"

# Server Configuration
PORT=3000
NODE_ENV="development"
CORS_ORIGIN="http://localhost:3000,http://localhost:3001"

# Redis Configuration
REDIS_URL="redis://localhost:6379"

# Email Configuration (Development - use Mailtrap or similar)
SMTP_HOST="sandbox.smtp.mailtrap.io"
SMTP_PORT=2525
SMTP_USER="your_mailtrap_user"
SMTP_PASS="your_mailtrap_password"
FROM_EMAIL="noreply@yourapp.com"

# Logging
LOG_LEVEL="debug"
LOG_FILE="logs/app.log"

# Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100

# Security
BCRYPT_ROUNDS=12
SESSION_SECRET="dev-session-secret"

# Super Admin (First time setup)
SUPER_ADMIN_EMAIL="admin@yourapp.com"
SUPER_ADMIN_PASSWORD="SuperSecure123!"
```

#### `.env.production`
```bash
# Database (Use environment-specific connection)
DATABASE_URL="postgresql://auth_user:secure_password@db-prod.amazonaws.com:5432/auth_prod"

# JWT Configuration (Use strong secrets in production)
JWT_SECRET="your-super-secure-jwt-secret-at-least-256-bits"
JWT_REFRESH_SECRET="your-super-secure-refresh-secret-at-least-256-bits"
ACCESS_TOKEN_EXPIRY="15m"
REFRESH_TOKEN_EXPIRY="7d"

# Server Configuration
PORT=3000
NODE_ENV="production"
CORS_ORIGIN="https://yourapp.com,https://admin.yourapp.com"

# Redis Configuration
REDIS_URL="redis://auth-redis.cache.amazonaws.com:6379"

# Email Configuration (Production - use SES, SendGrid, etc.)
SMTP_HOST="email-smtp.us-east-1.amazonaws.com"
SMTP_PORT=587
SMTP_USER="your_ses_access_key"
SMTP_PASS="your_ses_secret_key"
FROM_EMAIL="noreply@yourapp.com"

# Logging
LOG_LEVEL="info"
LOG_FILE="/var/log/auth-service/app.log"

# Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100

# Security
BCRYPT_ROUNDS=12
SESSION_SECRET="production-session-secret-very-secure"

# Monitoring
NEW_RELIC_LICENSE_KEY="your_new_relic_key"
SENTRY_DSN="your_sentry_dsn"

# Health Check
HEALTH_CHECK_ENDPOINT="/health"
```

#### `.env.staging`
```bash
# Similar to production but with staging-specific values
DATABASE_URL="postgresql://auth_user:password@db-staging.amazonaws.com:5432/auth_staging"
CORS_ORIGIN="https://staging.yourapp.com"
# ... other staging-specific configurations
```

---

## Database Setup

### 1. PostgreSQL Installation

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### CentOS/RHEL
```bash
sudo dnf install postgresql postgresql-server
sudo postgresql-setup --initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### Docker (Recommended for development)
```bash
docker run --name auth-postgres \
  -e POSTGRES_DB=auth_dev \
  -e POSTGRES_USER=auth_user \
  -e POSTGRES_PASSWORD=auth_password \
  -p 5432:5432 \
  -v postgres_data:/var/lib/postgresql/data \
  -d postgres:15
```

### 2. Database User Setup
```sql
-- Connect as postgres superuser
sudo -u postgres psql

-- Create database and user
CREATE DATABASE auth_prod;
CREATE USER auth_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE auth_prod TO auth_user;

-- Grant schema permissions
\c auth_prod
GRANT ALL ON SCHEMA public TO auth_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO auth_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO auth_user;

\q
```

### 3. Prisma Database Migration
```bash
# Generate Prisma client
npx prisma generate

# Run database migrations
npx prisma migrate deploy

# Seed initial data (optional)
npm run seed
```

### 4. Redis Setup

#### Using Docker
```bash
docker run --name auth-redis \
  -p 6379:6379 \
  -v redis_data:/data \
  -d redis:7-alpine \
  redis-server --appendonly yes
```

#### Ubuntu/Debian Installation
```bash
sudo apt update
sudo apt install redis-server
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

---

## Local Development

### 1. Start Development Server
```bash
# Using npm
npm run dev

# Using yarn
yarn dev

# With specific environment
NODE_ENV=development npm run dev
```

### 2. Development with Docker Compose
Create `docker-compose.dev.yml`:

```yaml
version: '3.8'

services:
  app:
    build: 
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
    env_file:
      - .env.development
    volumes:
      - .:/app
      - /app/node_modules
    depends_on:
      - postgres
      - redis
    command: npm run dev

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: auth_dev
      POSTGRES_USER: auth_user
      POSTGRES_PASSWORD: auth_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_dev_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_dev_data:/data

volumes:
  postgres_dev_data:
  redis_dev_data:
```

Start development environment:
```bash
docker-compose -f docker-compose.dev.yml up -d
```

---

## Production Deployment

### Docker Deployment

#### 1. Create Dockerfile
```dockerfile
# Multi-stage build for production
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY prisma ./prisma/

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Generate Prisma client
RUN npx prisma generate

# Production stage
FROM node:18-alpine AS production

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

WORKDIR /app

# Copy built application
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma
COPY . .

# Create logs directory
RUN mkdir -p logs && chown -R nodejs:nodejs logs

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["npm", "start"]
```

#### 2. Create Production Docker Compose
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    env_file:
      - .env.production
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    volumes:
      - ./logs:/app/logs
    networks:
      - auth-network

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: auth_prod
      POSTGRES_USER: auth_user
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    restart: unless-stopped
    networks:
      - auth-network

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    restart: unless-stopped
    networks:
      - auth-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - app
    restart: unless-stopped
    networks:
      - auth-network

secrets:
  db_password:
    file: ./secrets/db_password.txt

volumes:
  postgres_data:
  redis_data:

networks:
  auth-network:
    driver: bridge
```

#### 3. Nginx Configuration
Create `nginx.conf`:
```nginx
events {
    worker_connections 1024;
}

http {
    upstream auth_app {
        server app:3000;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;

    server {
        listen 80;
        server_name your-auth-domain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-auth-domain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

        location / {
            limit_req zone=auth burst=20 nodelay;
            
            proxy_pass http://auth_app;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }

        # Health check endpoint
        location /health {
            access_log off;
            proxy_pass http://auth_app;
        }
    }
}
```

#### 4. Deploy with Docker
```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f

# Scale the application
docker-compose up -d --scale app=3
```

---

### Cloud Deployment (AWS)

#### 1. AWS ECS with Fargate

**Task Definition (auth-service-task.json)**:
```json
{
  "family": "auth-service",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "auth-service",
      "image": "your-account.dkr.ecr.region.amazonaws.com/auth-service:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:auth-db-url"
        },
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/auth-service",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:3000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

**Deployment Script**:
```bash
#!/bin/bash

# Build and push to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin your-account.dkr.ecr.us-east-1.amazonaws.com

docker build -t auth-service .
docker tag auth-service:latest your-account.dkr.ecr.us-east-1.amazonaws.com/auth-service:latest
docker push your-account.dkr.ecr.us-east-1.amazonaws.com/auth-service:latest

# Register task definition
aws ecs register-task-definition --cli-input-json file://auth-service-task.json

# Update service
aws ecs update-service \
  --cluster auth-cluster \
  --service auth-service \
  --task-definition auth-service:LATEST \
  --desired-count 2
```

#### 2. AWS RDS Setup
```bash
# Create RDS PostgreSQL instance
aws rds create-db-instance \
  --db-instance-identifier auth-db-prod \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --engine-version 15.3 \
  --allocated-storage 20 \
  --db-name auth_prod \
  --master-username auth_user \
  --master-user-password SecurePassword123! \
  --vpc-security-group-ids sg-12345678 \
  --db-subnet-group-name auth-db-subnet-group
```

#### 3. AWS ElastiCache (Redis)
```bash
# Create Redis cluster
aws elasticache create-cache-cluster \
  --cache-cluster-id auth-redis-prod \
  --cache-node-type cache.t3.micro \
  --engine redis \
  --num-cache-nodes 1 \
  --security-group-ids sg-87654321
```

---

### Cloud Deployment (Google Cloud)

#### 1. Google Cloud Run
**cloudbuild.yaml**:
```yaml
steps:
  # Build the container image
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/auth-service', '.']

  # Push the container image to Container Registry
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/auth-service']

  # Deploy container image to Cloud Run
  - name: 'gcr.io/cloud-builders/gcloud'
    args:
    - 'run'
    - 'deploy'
    - 'auth-service'
    - '--image'
    - 'gcr.io/$PROJECT_ID/auth-service'
    - '--region'
    - 'us-central1'
    - '--platform'
    - 'managed'
    - '--allow-unauthenticated'
    - '--memory'
    - '1Gi'
    - '--cpu'
    - '1'
    - '--max-instances'
    - '10'
    - '--set-env-vars'
    - 'NODE_ENV=production'

images:
- gcr.io/$PROJECT_ID/auth-service
```

**Deploy Script**:
```bash
#!/bin/bash

# Set project
gcloud config set project your-project-id

# Build and deploy
gcloud builds submit --config cloudbuild.yaml

# Set environment variables (use Secret Manager for sensitive data)
gcloud run services update auth-service \
  --set-env-vars="NODE_ENV=production" \
  --set-secrets="DATABASE_URL=database-url:latest,JWT_SECRET=jwt-secret:latest" \
  --region=us-central1
```

#### 2. Google Cloud SQL
```bash
# Create PostgreSQL instance
gcloud sql instances create auth-db-prod \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --region=us-central1

# Create database and user
gcloud sql databases create auth_prod --instance=auth-db-prod
gcloud sql users create auth_user --instance=auth-db-prod --password=SecurePassword123!
```

---

### Cloud Deployment (Azure)

#### 1. Azure Container Instances
**deploy-azure.yml**:
```yaml
apiVersion: '2019-12-01'
location: eastus
name: auth-service-container-group
properties:
  containers:
  - name: auth-service
    properties:
      image: your-registry.azurecr.io/auth-service:latest
      resources:
        requests:
          cpu: 1
          memoryInGb: 1
      ports:
      - port: 3000
      environmentVariables:
      - name: NODE_ENV
        value: production
      - name: DATABASE_URL
        secureValue: postgresql://user:pass@server:5432/db
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    ports:
    - protocol: tcp
      port: 3000
tags: {}
type: Microsoft.ContainerInstance/containerGroups
```

**Deploy Script**:
```bash
#!/bin/bash

# Login to Azure
az login

# Create resource group
az group create --name auth-service-rg --location eastus

# Create container registry
az acr create --resource-group auth-service-rg --name authserviceregistry --sku Basic

# Build and push image
az acr build --registry authserviceregistry --image auth-service .

# Deploy container
az container create --resource-group auth-service-rg --file deploy-azure.yml
```

---

### VPS/Traditional Server

#### 1. Server Setup (Ubuntu 20.04+)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2
sudo npm install -g pm2

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Install Redis
sudo apt install redis-server

# Install Nginx
sudo apt install nginx

# Install certbot for SSL
sudo apt install certbot python3-certbot-nginx
```

#### 2. Application Deployment
```bash
# Create application user
sudo adduser authservice
sudo usermod -aG sudo authservice

# Switch to application user
sudo su - authservice

# Clone repository
git clone https://github.com/your-org/authentication-service.git
cd authentication-service

# Install dependencies
npm ci --production

# Generate Prisma client
npx prisma generate

# Run migrations
npx prisma migrate deploy

# Create PM2 ecosystem file
```

**ecosystem.config.js**:
```javascript
module.exports = {
  apps: [{
    name: 'auth-service',
    script: 'server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    env_file: '.env.production',
    error_file: '/var/log/auth-service/error.log',
    out_file: '/var/log/auth-service/out.log',
    log_file: '/var/log/auth-service/combined.log',
    time: true,
    max_memory_restart: '1G',
    node_args: '--max-old-space-size=1024'
  }]
};
```

#### 3. Start Application
```bash
# Create log directory
sudo mkdir -p /var/log/auth-service
sudo chown authservice:authservice /var/log/auth-service

# Start with PM2
pm2 start ecosystem.config.js

# Save PM2 configuration
pm2 save

# Setup PM2 startup script
pm2 startup
sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u authservice --hp /home/authservice
```

#### 4. Nginx Configuration
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

#### 5. SSL Setup
```bash
# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

---

## Monitoring and Logging

### 1. Application Monitoring
**Install monitoring packages**:
```bash
npm install newrelic @sentry/node winston
```

**Add to server.js**:
```javascript
// New Relic (add at the very top)
require('newrelic');

// Sentry
const Sentry = require('@sentry/node');
Sentry.init({ dsn: process.env.SENTRY_DSN });

// Winston logging
const winston = require('winston');
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});
```

### 2. Health Check Endpoint
```javascript
// routes/health.js
const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const redis = require('../config/redis');

const prisma = new PrismaClient();

router.get('/health', async (req, res) => {
  try {
    // Check database
    await prisma.$queryRaw`SELECT 1`;
    
    // Check Redis
    await redis.ping();
    
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: process.env.npm_package_version
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = router;
```

### 3. Prometheus Metrics
```bash
npm install prom-client
```

```javascript
// middleware/metrics.js
const promClient = require('prom-client');

// Create metrics
const httpDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code']
});

const httpRequests = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code']
});

// Middleware
const metricsMiddleware = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    const labels = {
      method: req.method,
      route: req.route?.path || req.path,
      status_code: res.statusCode
    };
    
    httpDuration.observe(labels, duration);
    httpRequests.inc(labels);
  });
  
  next();
};

module.exports = { metricsMiddleware, register: promClient.register };
```

---

## Security Considerations

### 1. Environment Security
```bash
# Secure file permissions
chmod 600 .env.production
chmod 700 logs/
chmod 755 scripts/

# Use environment-specific secrets
# AWS Secrets Manager, Azure Key Vault, or Google Secret Manager
```

### 2. Firewall Configuration
```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw deny 3000/tcp  # Block direct app access
sudo ufw enable
```

### 3. Database Security
```sql
-- Create read-only user for monitoring
CREATE USER monitoring WITH PASSWORD 'monitor_password';
GRANT CONNECT ON DATABASE auth_prod TO monitoring;
GRANT USAGE ON SCHEMA public TO monitoring;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO monitoring;

-- Revoke unnecessary permissions
REVOKE ALL ON SCHEMA public FROM PUBLIC;
```

### 4. Redis Security
```bash
# redis.conf
requirepass your_redis_password
bind 127.0.0.1
protected-mode yes
port 0
unixsocket /var/run/redis/redis.sock
unixsocketperm 700
```

---

## Backup and Recovery

### 1. Database Backup Script
```bash
#!/bin/bash
# backup-db.sh

DB_NAME="auth_prod"
DB_USER="auth_user"
BACKUP_DIR="/backups/database"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Create backup
pg_dump -h localhost -U $DB_USER -d $DB_NAME | gzip > $BACKUP_DIR/auth_backup_$DATE.sql.gz

# Keep only last 7 days of backups
find $BACKUP_DIR -name "auth_backup_*.sql.gz" -mtime +7 -delete

echo "Backup completed: auth_backup_$DATE.sql.gz"
```

### 2. Automated Backup with Cron
```bash
# Add to crontab
0 2 * * * /path/to/backup-db.sh >> /var/log/backup.log 2>&1
```

### 3. Application Backup
```bash
#!/bin/bash
# backup-app.sh

APP_DIR="/home/authservice/authentication-service"
BACKUP_DIR="/backups/application"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup
tar -czf $BACKUP_DIR/app_backup_$DATE.tar.gz -C $APP_DIR .

# Keep only last 5 backups
ls -t $BACKUP_DIR/app_backup_*.tar.gz | tail -n +6 | xargs rm -f

echo "Application backup completed: app_backup_$DATE.tar.gz"
```

---

## Troubleshooting

### 1. Common Issues

#### Application Won't Start
```bash
# Check logs
pm2 logs auth-service

# Check port availability
sudo netstat -tlnp | grep :3000

# Check environment variables
printenv | grep NODE_ENV

# Validate configuration
node -e "console.log(require('./config/database.js'))"
```

#### Database Connection Issues
```bash
# Test database connection
psql -h localhost -U auth_user -d auth_prod -c "SELECT version();"

# Check database logs
sudo tail -f /var/log/postgresql/postgresql-15-main.log

# Verify database URL
node -e "console.log(process.env.DATABASE_URL)"
```

#### Redis Connection Issues
```bash
# Test Redis connection
redis-cli ping

# Check Redis logs
sudo tail -f /var/log/redis/redis-server.log

# Test from application
node -e "const redis = require('./config/redis'); redis.ping().then(console.log).catch(console.error)"
```

### 2. Performance Issues
```bash
# Monitor system resources
htop
iotop
free -h
df -h

# Check PM2 processes
pm2 list
pm2 monit
pm2 show auth-service

# Database performance
sudo -u postgres psql -d auth_prod -c "
SELECT 
  query,
  calls,
  total_time,
  mean_time,
  rows
FROM pg_stat_statements 
ORDER BY total_time DESC 
LIMIT 10;"

# Redis performance
redis-cli --latency-history
redis-cli info memory
```

### 3. Memory Issues
```bash
# Check memory usage
pm2 show auth-service
free -h
cat /proc/meminfo

# Restart if memory leak detected
pm2 restart auth-service

# Monitor memory over time
pm2 install pm2-server-monit
```

### 4. Log Analysis
```bash
# Application logs
tail -f logs/combined.log
grep "ERROR" logs/error.log | tail -20

# System logs
sudo journalctl -u nginx -f
sudo tail -f /var/log/postgresql/postgresql-15-main.log

# PM2 logs
pm2 logs auth-service --lines 100
```

### 5. SSL Certificate Issues
```bash
# Check certificate status
sudo certbot certificates

# Test SSL configuration
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Renew certificate manually
sudo certbot renew --dry-run
sudo certbot renew --force-renewal
```

---

## Scaling and Load Balancing

### 1. Horizontal Scaling with PM2
```javascript
// ecosystem.config.js - Updated for scaling
module.exports = {
  apps: [{
    name: 'auth-service',
    script: 'server.js',
    instances: 0, // Use all CPU cores
    exec_mode: 'cluster',
    max_memory_restart: '500M',
    
    // Advanced PM2 features
    listen_timeout: 3000,
    kill_timeout: 5000,
    wait_ready: true,
    
    // Auto-restart on file changes (development only)
    watch: false,
    ignore_watch: ['node_modules', 'logs'],
    
    // Environment variables
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    
    // Logging
    log_date_format: 'YYYY-MM-DD HH:mm Z',
    merge_logs: true,
    
    // Advanced options
    node_args: '--max-old-space-size=512',
    
    // Graceful reload
    wait_ready: true,
    listen_timeout: 3000
  }]
};
```

### 2. Load Balancer Configuration (HAProxy)
```bash
# /etc/haproxy/haproxy.cfg
global
    daemon
    log stdout local0
    maxconn 4096
    
defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog
    log global
    
frontend auth_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/your-domain.pem
    redirect scheme https if !{ ssl_fc }
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request reject if { sc_http_req_rate(0) gt 20 }
    
    default_backend auth_backend
    
backend auth_backend
    balance roundrobin
    option httpchk GET /health
    
    server auth1 127.0.0.1:3000 check
    server auth2 127.0.0.1:3001 check
    server auth3 127.0.0.1:3002 check
```

### 3. Database Scaling
#### Read Replicas Setup
```sql
-- On master database
CREATE USER replicator WITH REPLICATION ENCRYPTED PASSWORD 'replica_password';

-- postgresql.conf on master
wal_level = replica
max_wal_senders = 3
wal_keep_segments = 64
archive_mode = on
archive_command = 'cp %p /var/lib/postgresql/15/main/archive/%f'

-- pg_hba.conf on master
host replication replicator replica_ip/32 md5
```

#### Connection Pooling
```javascript
// config/database.js - Connection pooling
const { Pool } = require('pg');

const poolConfig = {
  connectionString: process.env.DATABASE_URL,
  max: 20, // Maximum number of connections
  min: 2,  // Minimum number of connections
  idle: 10000, // Close connections after 10 seconds of inactivity
  acquire: 30000, // Maximum time to get connection
  evict: 1000, // Run eviction every second
  
  // Read replica configuration
  read: {
    host: process.env.DB_READ_HOST,
    replication: {
      read: [
        { host: process.env.DB_READ_REPLICA_1 },
        { host: process.env.DB_READ_REPLICA_2 }
      ]
    }
  }
};

const pool = new Pool(poolConfig);

module.exports = pool;
```

### 4. Redis Clustering
```bash
# Redis cluster setup (3 masters, 3 slaves)
# redis-cluster.conf
port 7000
cluster-enabled yes
cluster-config-file nodes.conf
cluster-node-timeout 5000
appendonly yes
```

```javascript
// config/redis-cluster.js
const Redis = require('ioredis');

const cluster = new Redis.Cluster([
  { port: 7000, host: 'redis-node-1' },
  { port: 7001, host: 'redis-node-2' },
  { port: 7002, host: 'redis-node-3' }
], {
  redisOptions: {
    password: process.env.REDIS_PASSWORD
  }
});

module.exports = cluster;
```

---

## CI/CD Pipeline

### 1. GitHub Actions Workflow
```yaml
# .github/workflows/deploy.yml
name: Deploy Authentication Service

on:
  push:
    branches: [main, staging]
  pull_request:
    branches: [main]

env:
  NODE_VERSION: '18'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: auth_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
          
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: 'npm'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Generate Prisma Client
      run: npx prisma generate
      
    - name: Run database migrations
      run: npx prisma migrate deploy
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/auth_test
        
    - name: Run tests
      run: npm test
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/auth_test
        REDIS_URL: redis://localhost:6379
        JWT_SECRET: test-secret
        NODE_ENV: test
        
    - name: Run security audit
      run: npm audit --audit-level high
      
    - name: Upload coverage reports
      uses: codecov/codecov-action@v3

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    if: github.event_name != 'pull_request'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Log in to Container Registry
      uses: docker/login-action@v2
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
        
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v4
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=sha,prefix={{branch}}-
          
    - name: Build and push Docker image
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}

  deploy-staging:
    needs: build-and-push
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/staging'
    environment: staging
    
    steps:
    - name: Deploy to staging
      run: |
        echo "Deploying to staging environment"
        # Add your staging deployment commands here
        
  deploy-production:
    needs: build-and-push
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    
    steps:
    - name: Deploy to production
      run: |
        echo "Deploying to production environment"
        # Add your production deployment commands here
```

### 2. GitLab CI/CD Pipeline
```yaml
# .gitlab-ci.yml
stages:
  - test
  - build
  - deploy

variables:
  DOCKER_HOST: tcp://docker:2376
  DOCKER_TLS_CERTDIR: "/certs"
  POSTGRES_DB: auth_test
  POSTGRES_USER: auth_user
  POSTGRES_PASSWORD: auth_password

services:
  - docker:20.10.16-dind
  - postgres:15
  - redis:7

before_script:
  - docker info

test:
  stage: test
  image: node:18
  script:
    - npm ci
    - npx prisma generate
    - npx prisma migrate deploy
    - npm test
  coverage: '/All files[^|]*\|[^|]*\s+([\d\.]+)/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml

build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main
    - staging

deploy_staging:
  stage: deploy
  script:
    - echo "Deploying to staging"
    # Add staging deployment script
  environment:
    name: staging
    url: https://auth-staging.yourapp.com
  only:
    - staging

deploy_production:
  stage: deploy
  script:
    - echo "Deploying to production"
    # Add production deployment script
  environment:
    name: production
    url: https://auth.yourapp.com
  when: manual
  only:
    - main
```

### 3. Deployment Scripts
```bash
#!/bin/bash
# scripts/deploy.sh

set -e

ENVIRONMENT=${1:-staging}
IMAGE_TAG=${2:-latest}

echo "Deploying to $ENVIRONMENT with tag $IMAGE_TAG"

case $ENVIRONMENT in
  staging)
    DOCKER_COMPOSE_FILE="docker-compose.staging.yml"
    ENV_FILE=".env.staging"
    ;;
  production)
    DOCKER_COMPOSE_FILE="docker-compose.production.yml"
    ENV_FILE=".env.production"
    ;;
  *)
    echo "Invalid environment: $ENVIRONMENT"
    exit 1
    ;;
esac

# Backup current deployment
echo "Creating backup..."
docker-compose -f $DOCKER_COMPOSE_FILE exec postgres pg_dump -U auth_user auth_${ENVIRONMENT} | gzip > backups/pre_deploy_$(date +%Y%m%d_%H%M%S).sql.gz

# Pull latest images
echo "Pulling latest images..."
docker-compose -f $DOCKER_COMPOSE_FILE pull

# Run database migrations
echo "Running migrations..."
docker-compose -f $DOCKER_COMPOSE_FILE run --rm app npx prisma migrate deploy

# Deploy with zero downtime
echo "Deploying application..."
docker-compose -f $DOCKER_COMPOSE_FILE up -d --remove-orphans

# Health check
echo "Performing health check..."
sleep 10
HEALTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)

if [ $HEALTH_CHECK -eq 200 ]; then
    echo "✅ Deployment successful!"
    
    # Clean up old images
    docker image prune -f
    
    # Send notification
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🚀 Auth service deployed to $ENVIRONMENT successfully!\"}" \
        $SLACK_WEBHOOK_URL
else
    echo "❌ Health check failed! Rolling back..."
    
    # Rollback logic here
    echo "Manual intervention required"
    exit 1
fi
```

---

## Maintenance and Updates

### 1. Regular Maintenance Tasks
```bash
#!/bin/bash
# scripts/maintenance.sh

echo "Starting maintenance tasks..."

# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Node.js dependencies
npm audit fix
npm update

# Database maintenance
sudo -u postgres psql -d auth_prod -c "VACUUM ANALYZE;"
sudo -u postgres psql -d auth_prod -c "REINDEX DATABASE auth_prod;"

# Log rotation
sudo logrotate -f /etc/logrotate.d/auth-service

# Clear old PM2 logs
pm2 flush

# Restart services for updates
pm2 reload ecosystem.config.js
sudo systemctl reload nginx

echo "Maintenance completed!"
```

### 2. Update Strategy
```bash
#!/bin/bash
# scripts/update.sh

# Blue-Green Deployment Strategy
CURRENT_PORT=$(pm2 show auth-service | grep "port" | awk '{print $4}')
NEW_PORT=$((CURRENT_PORT == 3000 ? 3001 : 3000))

echo "Current service running on port $CURRENT_PORT"
echo "Starting new service on port $NEW_PORT"

# Start new version
PORT=$NEW_PORT pm2 start ecosystem.config.js --name auth-service-new

# Health check new version
sleep 10
if curl -f http://localhost:$NEW_PORT/health; then
    echo "New version healthy, switching traffic..."
    
    # Update nginx configuration
    sed -i "s/localhost:$CURRENT_PORT/localhost:$NEW_PORT/g" /etc/nginx/sites-available/auth-service
    sudo nginx -s reload
    
    # Stop old version
    pm2 stop auth-service
    pm2 delete auth-service
    
    # Rename new version
    pm2 restart auth-service-new --name auth-service
    
    echo "Deployment successful!"
else
    echo "New version failed health check, rolling back..."
    pm2 stop auth-service-new
    pm2 delete auth-service-new
    exit 1
fi
```

### 3. Monitoring Scripts
```bash
#!/bin/bash
# scripts/monitor.sh

# System health monitoring
check_service() {
    SERVICE=$1
    if systemctl is-active --quiet $SERVICE; then
        echo "✅ $SERVICE is running"
    else
        echo "❌ $SERVICE is down"
        # Send alert
        echo "Service $SERVICE is down!" | mail -s "Service Alert" admin@yourapp.com
    fi
}

check_service nginx
check_service postgresql
check_service redis

# Application health
APP_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)
if [ $APP_HEALTH -eq 200 ]; then
    echo "✅ Application is healthy"
else
    echo "❌ Application health check failed"
    # Restart application
    pm2 restart auth-service
fi

# Database health
DB_HEALTH=$(sudo -u postgres psql -d auth_prod -t -c "SELECT 1;" 2>/dev/null | xargs)
if [ "$DB_HEALTH" = "1" ]; then
    echo "✅ Database is healthy"
else
    echo "❌ Database health check failed"
fi

# Disk space check
DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "⚠️  Disk usage is at $DISK_USAGE%"
    # Clean up logs
    find /var/log -name "*.log" -mtime +7 -delete
fi
```

---

## Final Checklist

### Pre-deployment Checklist
- [ ] Environment variables configured
- [ ] Database migrations tested
- [ ] SSL certificates obtained
- [ ] Firewall rules configured
- [ ] Backup strategy implemented
- [ ] Monitoring setup completed
- [ ] Load testing performed
- [ ] Security audit completed
- [ ] Documentation updated
- [ ] Team training completed

### Post-deployment Checklist
- [ ] Health checks passing
- [ ] Logs are being generated
- [ ] Monitoring alerts configured
- [ ] Performance metrics baseline established
- [ ] Backup jobs scheduled
- [ ] SSL certificate auto-renewal working
- [ ] Load balancer health checks configured
- [ ] Disaster recovery plan tested
- [ ] Team access verified
- [ ] Client applications tested

### Emergency Procedures
1. **Service Down**: Check logs, restart services, verify dependencies
2. **Database Issues**: Check connections, run health queries, restore from backup if needed
3. **High CPU/Memory**: Scale horizontally, restart services, investigate memory leaks
4. **SSL Expiry**: Renew certificates immediately, update load balancers
5. **Security Breach**: Rotate secrets, audit logs, notify stakeholders

---

This comprehensive deployment guide covers everything needed to successfully deploy your authentication microservice in any environment, from development to enterprise production setups.