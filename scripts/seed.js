const { PrismaClient } = require('@prisma/client');
const { hashPassword } = require('../utils/hash');

const prisma = new PrismaClient();

async function main() {
    try {
        console.log('🌱 Starting database seeding...');

        // Create demo organization
        const organization = await prisma.organization.upsert({
            where: { slug: 'demo-company' },
            update: {},
            create: {
                name: 'Demo Company',
                slug: 'demo-company',
                email: 'contact@democompany.com',
                website: 'https://democompany.com',
                settings: {
                    allowUserRegistration: true,
                    emailVerificationRequired: true,
                    passwordPolicy: {
                        minLength: 8,
                        requireUppercase: true,
                        requireLowercase: true,
                        requireNumbers: true,
                        requireSpecialChars: true
                    }
                }
            }
        });

        console.log('✅ Created organization:', organization.name);

        // Create roles
        const adminRole = await prisma.role.upsert({
            where: {
                slug_organizationId: {
                    slug: 'admin',
                    organizationId: organization.id
                }
            },
            update: {},
            create: {
                name: 'Admin',
                slug: 'admin',
                description: 'Full access to all features',
                permissions: [
                    'users.create',
                    'users.read',
                    'users.update',
                    'users.delete',
                    'users.invite',
                    'roles.create',
                    'roles.read',
                    'roles.update',
                    'roles.delete',
                    'roles.assign',
                    'organization.read',
                    'organization.update',
                    'organization.settings',
                    'sessions.read',
                    'sessions.revoke',
                    'api-keys.create',
                    'api-keys.read',
                    'api-keys.delete',
                    'invitations.send',
                    'invitations.read',
                    'invitations.revoke'
                ],
                organizationId: organization.id,
                isDefault: false
            }
        });

        const memberRole = await prisma.role.upsert({
            where: {
                slug_organizationId: {
                    slug: 'member',
                    organizationId: organization.id
                }
            },
            update: {},
            create: {
                name: 'Member',
                slug: 'member',
                description: 'Standard user access',
                permissions: [
                    'users.read',
                    'organization.read'
                ],
                organizationId: organization.id,
                isDefault: true
            }
        });

        const viewerRole = await prisma.role.upsert({
            where: {
                slug_organizationId: {
                    slug: 'viewer',
                    organizationId: organization.id
                }
            },
            update: {},
            create: {
                name: 'Viewer',
                slug: 'viewer',
                description: 'Read-only access',
                permissions: [
                    'users.read',
                    'organization.read'
                ],
                organizationId: organization.id,
                isDefault: false
            }
        });

        console.log('✅ Created roles: Admin, Member, Viewer');

        // Create demo admin user
        const hashedPassword = await hashPassword('Admin123!');

        const adminUser = await prisma.user.upsert({
            where: { email: 'admin@democompany.com' },
            update: {},
            create: {
                email: 'admin@democompany.com',
                password: hashedPassword,
                firstName: 'Admin',
                lastName: 'User',
                isEmailVerified: true,
                emailVerifiedAt: new Date(),
                organizationId: organization.id
            }
        });

        // Assign admin role to admin user
        await prisma.userRole.upsert({
            where: {
                userId_roleId: {
                    userId: adminUser.id,
                    roleId: adminRole.id
                }
            },
            update: {},
            create: {
                userId: adminUser.id,
                roleId: adminRole.id
            }
        });

        console.log('✅ Created admin user: admin@democompany.com (password: Admin123!)');

        // Create demo regular user
        const memberUser = await prisma.user.upsert({
            where: { email: 'user@democompany.com' },
            update: {},
            create: {
                email: 'user@democompany.com',
                password: hashedPassword,
                firstName: 'John',
                lastName: 'Doe',
                isEmailVerified: true,
                emailVerifiedAt: new Date(),
                organizationId: organization.id
            }
        });

        // Assign member role to regular user
        await prisma.userRole.upsert({
            where: {
                userId_roleId: {
                    userId: memberUser.id,
                    roleId: memberRole.id
                }
            },
            update: {},
            create: {
                userId: memberUser.id,
                roleId: memberRole.id
            }
        });

        console.log('✅ Created member user: user@democompany.com (password: Admin123!)');

        // Create demo viewer user
        const viewerUser = await prisma.user.upsert({
            where: { email: 'viewer@democompany.com' },
            update: {},
            create: {
                email: 'viewer@democompany.com',
                password: hashedPassword,
                firstName: 'Jane',
                lastName: 'Smith',
                isEmailVerified: true,
                emailVerifiedAt: new Date(),
                organizationId: organization.id
            }
        });

        // Assign viewer role to viewer user
        await prisma.userRole.upsert({
            where: {
                userId_roleId: {
                    userId: viewerUser.id,
                    roleId: viewerRole.id
                }
            },
            update: {},
            create: {
                userId: viewerUser.id,
                roleId: viewerRole.id
            }
        });

        console.log('✅ Created viewer user: viewer@democompany.com (password: Admin123!)');

        console.log(`
🎉 Database seeding completed successfully!

Demo Organization: ${organization.name}
- Slug: ${organization.slug}
- Email: ${organization.email}

Demo Users:
1. Admin User
   - Email: admin@democompany.com
   - Password: Admin123!
   - Role: Admin
   - Permissions: Full access

2. Member User
   - Email: user@democompany.com
   - Password: Admin123!
   - Role: Member
   - Permissions: Standard user access

3. Viewer User
   - Email: viewer@democompany.com
   - Password: Admin123!
   - Role: Viewer
   - Permissions: Read-only access

You can now test the authentication service with these demo accounts.
    `);

    } catch (error) {
        console.error('❌ Seeding failed:', error);
        throw error;
    }
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });