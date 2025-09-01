const { PrismaClient } = require('@prisma/client');
const { hashPassword } = require('../utils/hash');

const prisma = new PrismaClient();

async function main() {
    try {
        console.log('🌱 Starting database seeding...');

        // Create super admin first (no organization needed)
        const superAdminPassword = await hashPassword('SuperAdmin123!');

        const superAdmin = await prisma.user.upsert({
            where: { email: 'superadmin@system.com' },
            update: {},
            create: {
                email: 'superadmin@system.com',
                password: superAdminPassword,
                firstName: 'Super',
                lastName: 'Admin',
                isSuperAdmin: true,
                isEmailVerified: true,
                emailVerifiedAt: new Date(),
                organizationId: null // Super admins don't belong to any organization
            }
        });

        console.log('✅ Created super admin: superadmin@system.com (password: SuperAdmin123!)');

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

        // Create roles for the demo organization
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
                description: 'Full access to all features within organization',
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

        // Create demo organization users
        const regularPassword = await hashPassword('Admin123!');

        // Create demo admin user
        const adminUser = await prisma.user.upsert({
            where: { email: 'admin@democompany.com' },
            update: {},
            create: {
                email: 'admin@democompany.com',
                password: regularPassword,
                firstName: 'Admin',
                lastName: 'User',
                isEmailVerified: true,
                emailVerifiedAt: new Date(),
                organizationId: organization.id,
                isSuperAdmin: false
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

        console.log('✅ Created organization admin: admin@democompany.com (password: Admin123!)');

        // Create demo regular user
        const memberUser = await prisma.user.upsert({
            where: { email: 'user@democompany.com' },
            update: {},
            create: {
                email: 'user@democompany.com',
                password: regularPassword,
                firstName: 'John',
                lastName: 'Doe',
                isEmailVerified: true,
                emailVerifiedAt: new Date(),
                organizationId: organization.id,
                isSuperAdmin: false
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
                password: regularPassword,
                firstName: 'Jane',
                lastName: 'Smith',
                isEmailVerified: true,
                emailVerifiedAt: new Date(),
                organizationId: organization.id,
                isSuperAdmin: false
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

        // Create a second demo organization to showcase multi-tenancy
        const organization2 = await prisma.organization.upsert({
            where: { slug: 'acme-corp' },
            update: {},
            create: {
                name: 'Acme Corporation',
                slug: 'acme-corp',
                email: 'info@acmecorp.com',
                website: 'https://acmecorp.com',
                settings: {
                    allowUserRegistration: false,
                    emailVerificationRequired: true,
                    passwordPolicy: {
                        minLength: 10,
                        requireUppercase: true,
                        requireLowercase: true,
                        requireNumbers: true,
                        requireSpecialChars: true
                    }
                }
            }
        });

        // Create roles for the second organization (roles are organization-specific)
        const acmeAdminRole = await prisma.role.upsert({
            where: {
                slug_organizationId: {
                    slug: 'admin',
                    organizationId: organization2.id
                }
            },
            update: {},
            create: {
                name: 'Admin',
                slug: 'admin',
                description: 'Full access to all features within organization',
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
                organizationId: organization2.id,
                isDefault: false
            }
        });

        const acmeMemberRole = await prisma.role.upsert({
            where: {
                slug_organizationId: {
                    slug: 'member',
                    organizationId: organization2.id
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
                organizationId: organization2.id,
                isDefault: true
            }
        });

        // Create admin for second organization
        const acmeAdmin = await prisma.user.upsert({
            where: { email: 'admin@acmecorp.com' },
            update: {},
            create: {
                email: 'admin@acmecorp.com',
                password: regularPassword,
                firstName: 'Alice',
                lastName: 'Johnson',
                isEmailVerified: true,
                emailVerifiedAt: new Date(),
                organizationId: organization2.id,
                isSuperAdmin: false
            }
        });

        await prisma.userRole.create({
            data: {
                userId: acmeAdmin.id,
                roleId: acmeAdminRole.id
            }
        });

        console.log('✅ Created second organization: Acme Corporation');
        console.log('✅ Created Acme admin: admin@acmecorp.com (password: Admin123!)');

        console.log(`
🎉 Database seeding completed successfully!

SUPER ADMIN:
- Email: superadmin@system.com
- Password: SuperAdmin123!
- Access: Full system access via /api/super-admin routes
- Can manage all organizations and users

DEMO ORGANIZATIONS:

1. Demo Company (demo-company)
   - Email: contact@democompany.com
   - Website: https://democompany.com
   
   Users:
   • Admin: admin@democompany.com (Admin123!) - Organization Admin
   • Member: user@democompany.com (Admin123!) - Standard User
   • Viewer: viewer@democompany.com (Admin123!) - Read-only User

2. Acme Corporation (acme-corp)
   - Email: info@acmecorp.com
   - Website: https://acmecorp.com
   
   Users:
   • Admin: admin@acmecorp.com (Admin123!) - Organization Admin

TESTING MULTI-TENANCY:
- Users from Demo Company cannot access Acme Corporation data
- Super Admin can access all organizations
- Each organization has its own roles and permissions

API ENDPOINTS:
- Regular auth: /api/auth/*
- Super admin: /api/super-admin/*
- Organizations: /api/organizations/*
- Users: /api/users/*
- Roles: /api/roles/*

Remember to update your Prisma schema to include the isSuperAdmin field before running this seed!
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