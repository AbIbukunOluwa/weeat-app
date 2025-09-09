require('dotenv').config();
const { sequelize, User, Order, Complaint, Vulnerability, Food, Review } = require('./models');

(async () => {
  try {
    await sequelize.sync({ force: true });
    console.log('🗑️  Database synced and cleared!');

    // Create users with intentional vulnerabilities
    const users = [
      { 
        name: 'Alice Customer', 
        username: 'alice', 
        email: 'alice@example.com', 
        role: 'customer', 
        password: 'alice123' 
      },
      { 
        name: 'Bob Customer', 
        username: 'bob', 
        email: 'bob@example.com', 
        role: 'customer', 
        password: 'bob123' 
      },
      { 
        name: 'Charlie Staff', 
        username: 'charlie', 
        email: 'charlie@weeat.com', 
        role: 'staff', 
        password: 'charlie123' 
      },
      { 
        name: 'Diana Admin', 
        username: 'diana', 
        email: 'diana@weeat.com', 
        role: 'admin', 
        password: 'diana123' 
      },
      // VULNERABILITY A07: Default/weak credentials
      { 
        name: 'System Admin', 
        username: 'admin', 
        email: 'admin@weeat.com', 
        role: 'admin', 
        password: 'admin' // Weak default password
      },
      { 
        name: 'Test User', 
        username: 'test', 
        email: 'test@weeat.com', 
        role: 'customer', 
        password: '123' // Very weak password
      }
    ];

    console.log('👥 Creating users...');
    for (const u of users) {
      const user = await User.create({ 
        name: u.name, 
        username: u.username, 
        email: u.email, 
        passwordHash: 'temp',
        role: u.role 
      });
      await user.setPassword(u.password);
      await user.save();
      console.log(`   ✓ ${u.username} (${u.role})`);
    }

    // Create food items
    const foods = [
      { 
        name: 'Crispy Fries', 
        image: 'https://images.unsplash.com/photo-1541592106381-b31e9677c0e5?w=500', 
        price: 3.99,
        category: 'sides',
        description: 'Golden crispy french fries'
      },
      { 
        name: 'Vanilla Ice Cream', 
        image: 'https://images.unsplash.com/photo-1580915411954-282cb1b0d780?w=500', 
        price: 2.99,
        category: 'desserts',
        description: 'Creamy vanilla ice cream'
      },
      { 
        name: 'Jollof Rice', 
        image: 'https://plus.unsplash.com/premium_photo-1694141252774-c937d97641da?w=500', 
        price: 8.99,
        category: 'mains',
        description: 'Traditional West African rice dish'
      },
      { 
        name: 'Spicy Noodles', 
        image: 'https://images.unsplash.com/photo-1612929633738-8fe44f7ec841?w=500', 
        price: 6.99,
        category: 'mains',
        description: 'Hot and spicy Asian noodles'
      },
      { 
        name: 'Fried Chicken', 
        image: 'https://images.unsplash.com/photo-1626645738196-c2a7c87a8f58?w=500', 
        price: 9.99,
        category: 'mains',
        description: 'Crispy fried chicken pieces'
      },
      { 
        name: 'Buffalo Wings', 
        image: 'https://plus.unsplash.com/premium_photo-1672498193267-4f0e8c819bc8?w=500', 
        price: 7.99,
        category: 'appetizers',
        description: 'Spicy buffalo chicken wings'
      },
      { 
        name: 'Classic Burger', 
        image: 'https://images.unsplash.com/photo-1667329829058-ac191ba4a905?w=500', 
        price: 5.99,
        category: 'mains',
        description: 'Juicy beef burger with all the fixings'
      },
      { 
        name: 'Chicken Wraps', 
        image: 'https://plus.unsplash.com/premium_photo-1678051305065-1cd54b84272e?w=500', 
        price: 6.99,
        category: 'mains',
        description: 'Grilled chicken wrap with fresh vegetables'
      },
      { 
        name: 'Soft Drinks', 
        image: 'https://images.unsplash.com/photo-1630979805425-08f5f5f39aff?w=500', 
        price: 2.49,
        category: 'beverages',
        description: 'Refreshing soft drinks'
      },
      { 
        name: 'Margherita Pizza', 
        image: 'https://plus.unsplash.com/premium_photo-1667682942148-a0c98d1d70db?w=500', 
        price: 12.99,
        category: 'mains',
        description: 'Classic pizza with tomato sauce and mozzarella'
      }
    ];

    console.log('🍔 Creating food items...');
    await Food.bulkCreate(foods);
    console.log(`   ✓ ${foods.length} food items created`);

    // Create sample orders
    const orders = [
      { 
        items: JSON.stringify([
          { name: 'Margherita Pizza', price: 12.99, qty: 1 },
          { name: 'Soft Drinks', price: 2.49, qty: 2 }
        ]), 
        totalAmount: 17.97, 
        status: 'pending', 
        userId: 1 
      },
      { 
        items: JSON.stringify([
          { name: 'Classic Burger', price: 5.99, qty: 1 },
          { name: 'Crispy Fries', price: 3.99, qty: 1 }
        ]), 
        totalAmount: 9.98, 
        status: 'preparing', 
        userId: 2 
      },
      { 
        items: JSON.stringify([
          { name: 'Fried Chicken', price: 9.99, qty: 2 },
          { name: 'Buffalo Wings', price: 7.99, qty: 1 }
        ]), 
        totalAmount: 27.97, 
        status: 'delivered', 
        userId: 1 
      }
    ];

    console.log('📦 Creating sample orders...');
    await Order.bulkCreate(orders);
    console.log(`   ✓ ${orders.length} orders created`);

    // Create sample complaints
    const complaints = [
      { 
        orderId: '1', 
        details: 'Pizza was cold when delivered', 
        photo: null, 
        userId: 1 
      },
      { 
        orderId: '2', 
        details: 'Wrong order received - got chicken instead of burger', 
        photo: null, 
        userId: 2 
      },
      { 
        orderId: '3', 
        details: 'Delivery was 2 hours late', 
        photo: null, 
        userId: 1 
      }
    ];

    console.log('💬 Creating complaints...');
    await Complaint.bulkCreate(complaints);
    console.log(`   ✓ ${complaints.length} complaints created`);

    // Create vulnerabilities for tracking
    const vulnerabilities = [
      {
        title: 'SQL Injection in Menu Search',
        description: 'Raw SQL query allows injection via search parameter',
        severity: 'critical',
        resolved: false,
        assignedTo: 4, // Admin user
        flag: 'WeEat{SQL_1nj3ct10n_M3nu_S34rch}',
        found: false
      },
      {
        title: 'Broken Access Control - Admin Panel',
        description: 'Any user can access admin functions with role parameter',
        severity: 'high',
        resolved: false,
        assignedTo: 4,
        flag: 'WeEat{Br0k3n_4cc355_C0ntr0l}',
        found: false
      },
      {
        title: 'Insecure Direct Object Reference',
        description: 'Users can view other users\' orders without authorization',
        severity: 'high',
        resolved: false,
        assignedTo: 3,
        flag: 'WeEat{1D0R_0rd3r_4cc355}',
        found: false
      },
      {
        title: 'Cross-Site Scripting (XSS)',
        description: 'User input not properly sanitized in complaints',
        severity: 'medium',
        resolved: false,
        assignedTo: 3,
        flag: 'WeEat{XSS_C0mpl41nt_F0rm}',
        found: false
      },
      {
        title: 'Sensitive Data Exposure',
        description: 'Database credentials and system info exposed in error messages',
        severity: 'medium',
        resolved: false,
        assignedTo: 4,
        flag: 'WeEat{S3ns1t1v3_D4t4_3xp0sur3}',
        found: false
      },
      {
        title: 'Weak Authentication',
        description: 'Default admin credentials and weak password policy',
        severity: 'high',
        resolved: false,
        assignedTo: 4,
        flag: 'WeEat{W34k_4uth3nt1c4t10n}',
        found: false
      },
      {
        title: 'Price Manipulation',
        description: 'Client-side price validation allows price tampering',
        severity: 'critical',
        resolved: false,
        assignedTo: 4,
        flag: 'WeEat{Pr1c3_M4n1pul4t10n}',
        found: false
      },
      {
        title: 'Insufficient Logging',
        description: 'Critical security events not properly logged',
        severity: 'low',
        resolved: false,
        assignedTo: 3,
        flag: 'WeEat{1nsuff1c13nt_L0gg1ng}',
        found: false
      },
      {
        title: 'Server-Side Request Forgery',
        description: 'Image URL validation allows internal network access',
        severity: 'high',
        resolved: false,
        assignedTo: 4,
        flag: 'WeEat{SSRF_1m4g3_Upl04d}',
        found: false
      },
      {
        title: 'Unrestricted File Upload',
        description: 'No validation on file uploads in admin panel',
        severity: 'high',
        resolved: false,
        assignedTo: 4,
        flag: 'WeEat{Unr35tr1ct3d_F1l3_Upl04d}',
        found: false
      }
    ];

    console.log('🐛 Creating vulnerabilities...');
    await Vulnerability.bulkCreate(vulnerabilities);
    console.log(`   ✓ ${vulnerabilities.length} vulnerabilities created`);

    // Create session table for PostgreSQL session store
    try {
      await sequelize.query(`
        CREATE TABLE IF NOT EXISTS session (
          sid VARCHAR NOT NULL COLLATE "default",
          sess JSON NOT NULL,
          expire TIMESTAMP(6) NOT NULL
        ) WITH (OIDS=FALSE);
        ALTER TABLE session ADD CONSTRAINT session_pkey PRIMARY KEY (sid) NOT DEFERRABLE INITIALLY IMMEDIATE;
        CREATE INDEX IF NOT EXISTS IDX_session_expire ON session(expire);
      `);
      console.log('🔐 Session table created');
    } catch (sessionErr) {
      console.log('ℹ️  Session table already exists or created');
    }

    console.log('\n🎉 Seeding complete!');
    console.log('\n📋 Test Accounts:');
    console.log('   👤 Customer: alice@example.com / alice123');
    console.log('   👤 Customer: bob@example.com / bob123');
    console.log('   👨‍💼 Staff: charlie@weeat.com / charlie123');
    console.log('   👩‍💻 Admin: diana@weeat.com / diana123');
    console.log('   🚨 Vulnerable: admin@weeat.com / admin');
    console.log('   🚨 Weak Auth: test@weeat.com / 123');
    
    console.log('\n🎯 Vulnerability Flags Created:');
    vulnerabilities.forEach((v, i) => {
      console.log(`   ${i + 1}. ${v.title} (${v.severity})`);
    });
    
    console.log('\n🚀 Start the app with: npm start');
    console.log('🌐 Visit: http://localhost:3000');
    
    process.exit(0);
  } catch (err) {
    console.error('❌ Seeding failed:', err);
    process.exit(1);
  }
})();
