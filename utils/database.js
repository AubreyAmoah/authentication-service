const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['query', 'info', 'warn'] : ['error'],
    errorFormat: 'pretty'
});

// Test database connection
const connectDatabase = async () => {
    try {
        await prisma.$connect();
        console.log('✅ Database connected successfully');
    } catch (error) {
        console.error('❌ Database connection failed:', error);
        process.exit(1);
    }
};

// Graceful shutdown
const disconnectDatabase = async () => {
    await prisma.$disconnect();
    console.log('📴 Database disconnected');
};

// Handle process termination
process.on('SIGINT', async () => {
    await disconnectDatabase();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    await disconnectDatabase();
    process.exit(0);
});

module.exports = {
    prisma,
    connectDatabase,
    disconnectDatabase
};