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

    // Create comprehensive food menu with real images
    const foods = [
      // Fries Variations
      { 
        name: 'Classic Crispy Fries', 
        image: 'https://images.unsplash.com/photo-1541592106381-b31e9677c0e5?w=500&auto=format&fit=crop&q=60', 
        price: 3.99,
        category: 'sides',
        description: 'Golden crispy french fries with sea salt',
        status: 'active'
      },
      { 
        name: 'Loaded Cheese Fries', 
        image: 'https://images.unsplash.com/photo-1608219994488-cc269412b3e4?w=500&auto=format&fit=crop&q=60', 
        price: 5.99,
        category: 'sides',
        description: 'Fries topped with melted cheese and bacon bits',
        status: 'active'
      },
      
      // Ice Cream Variations
      { 
        name: 'Vanilla Soft Serve', 
        image: 'https://images.unsplash.com/photo-1580915411954-282cb1b0d780?w=500&auto=format&fit=crop&q=60', 
        price: 2.99,
        category: 'desserts',
        description: 'Creamy vanilla soft serve ice cream',
        status: 'active'
      },
      { 
        name: 'Strawberry Sundae', 
        image: 'https://images.unsplash.com/photo-1633933358116-a27b902fad35?w=500&auto=format&fit=crop&q=60', 
        price: 4.49,
        category: 'desserts',
        description: 'Premium ice cream with fresh strawberry topping',
        status: 'active'
      },
      
      // Jollof Rice Variations
      { 
        name: 'Classic Jollof Rice', 
        image: 'https://plus.unsplash.com/premium_photo-1694141252774-c937d97641da?w=500&auto=format&fit=crop&q=60', 
        price: 8.99,
        category: 'mains',
        description: 'Traditional West African rice dish with tomatoes and spices',
        status: 'active'
      },
      { 
        name: 'Jollof Rice Combo', 
        image: 'https://plus.unsplash.com/premium_photo-1694141250007-fc4711bb9df1?w=500&auto=format&fit=crop&q=60', 
        price: 11.99,
        category: 'mains',
        description: 'Jollof rice with grilled chicken and plantains',
        status: 'active'
      },
      
      // Noodles Variations
      { 
        name: 'Spicy Asian Noodles', 
        image: 'https://images.unsplash.com/photo-1612929633738-8fe44f7ec841?w=500&auto=format&fit=crop&q=60', 
        price: 6.99,
        category: 'mains',
        description: 'Hot and spicy stir-fried noodles with vegetables',
        status: 'active'
      },
      { 
        name: 'Chicken Pad Thai', 
        image: 'https://images.unsplash.com/photo-1592778024292-d6782d22add7?w=500&auto=format&fit=crop&q=60', 
        price: 9.49,
        category: 'mains',
        description: 'Thai-style noodles with chicken and peanuts',
        status: 'active'
      },
      
      // Fried Chicken Variations
      { 
        name: 'Crispy Fried Chicken (3pc)', 
        image: 'https://images.unsplash.com/photo-1626645738196-c2a7c87a8f58?w=500&auto=format&fit=crop&q=60', 
        price: 9.99,
        category: 'mains',
        description: 'Three pieces of our signature crispy fried chicken',
        status: 'active'
      },
      { 
        name: 'Nashville Hot Chicken', 
        image: 'https://images.unsplash.com/photo-1588923930978-3f8c78001ec5?w=500&auto=format&fit=crop&q=60', 
        price: 10.99,
        category: 'mains',
        description: 'Spicy Nashville-style hot chicken sandwich',
        status: 'active'
      },
      
      // Wings Variations
      { 
        name: 'Buffalo Wings (6pc)', 
        image: 'https://plus.unsplash.com/premium_photo-1672498193267-4f0e8c819bc8?w=500&auto=format&fit=crop&q=60', 
        price: 7.99,
        category: 'appetizers',
        description: 'Classic buffalo chicken wings with blue cheese dip',
        status: 'active'
      },
      { 
        name: 'BBQ Wings (12pc)', 
        image: 'https://plus.unsplash.com/premium_photo-1669742928218-b1111a31f7c1?w=500&auto=format&fit=crop&q=60', 
        price: 14.99,
        category: 'appetizers',
        description: 'Smoky BBQ glazed chicken wings',
        status: 'active'
      },
      
      // Burger Variations
      { 
        name: 'Classic Beef Burger', 
        image: 'https://images.unsplash.com/photo-1667329829058-ac191ba4a905?w=500&auto=format&fit=crop&q=60', 
        price: 5.99,
        category: 'mains',
        description: 'Juicy beef patty with lettuce, tomato, and special sauce',
        status: 'active'
      },
      { 
        name: 'Double Bacon Cheeseburger', 
        image: 'https://images.unsplash.com/photo-1586190848861-99aa4a171e90?w=500&auto=format&fit=crop&q=60', 
        price: 8.99,
        category: 'mains',
        description: 'Two beef patties with bacon, cheese, and all the fixings',
        status: 'active'
      },
      
      // Wraps Variations
      { 
        name: 'Grilled Chicken Wrap', 
        image: 'https://plus.unsplash.com/premium_photo-1678051305065-1cd54b84272e?w=500&auto=format&fit=crop&q=60', 
        price: 6.99,
        category: 'mains',
        description: 'Grilled chicken with fresh vegetables in a tortilla wrap',
        status: 'active'
      },
      { 
        name: 'Veggie Delight Wrap', 
        image: 'https://plus.unsplash.com/premium_photo-1679287668420-80c27ea4fb31?w=500&auto=format&fit=crop&q=60', 
        price: 5.99,
        category: 'mains',
        description: 'Fresh vegetables and hummus in a whole wheat wrap',
        status: 'active'
      },
      
      // Drinks Variations
      { 
        name: 'Soft Drinks (Regular)', 
        image: 'https://images.unsplash.com/photo-1630979805425-08f5f5f39aff?w=500&auto=format&fit=crop&q=60', 
        price: 2.49,
        category: 'beverages',
        description: 'Choice of Coke, Sprite, or Fanta',
        status: 'active'
      },
      { 
        name: 'Soft Drinks (Large)', 
        image: 'https://images.unsplash.com/photo-1581006852262-e4307cf6283a?w=500&auto=format&fit=crop&q=60', 
        price: 3.49,
        category: 'beverages',
        description: 'Large size soft drink with free refills',
        status: 'active'
      },
      { 
        name: 'Fresh Lemonade', 
        image: 'https://images.unsplash.com/photo-1579630942078-100a2f8e9052?w=500&auto=format&fit=crop&q=60', 
        price: 3.99,
        category: 'beverages',
        description: 'Freshly squeezed lemonade with mint',
        status: 'active'
      },
      
      // Pizza Variations
      { 
        name: 'Margherita Pizza', 
        image: 'https://plus.unsplash.com/premium_photo-1667682942148-a0c98d1d70db?w=500&auto=format&fit=crop&q=60', 
        price: 12.99,
        category: 'mains',
        description: 'Classic pizza with fresh mozzarella and basil',
        status: 'active'
      },
      { 
        name: 'Pepperoni Deluxe Pizza', 
        image: 'https://images.unsplash.com/photo-1615719413546-198b25453f85?w=500&auto=format&fit=crop&q=60', 
        price: 14.99,
        category: 'mains',
        description: 'Loaded with double pepperoni and extra cheese',
        status: 'active'
      },
      
      // Additional items for variety
      { 
        name: 'Onion Rings', 
        image: 'https://images.unsplash.com/photo-1639024471283-03518883512d?w=500&auto=format&fit=crop&q=60', 
        price: 4.49,
        category: 'sides',
        description: 'Crispy battered onion rings',
        status: 'active'
      },
      { 
        name: 'Mozzarella Sticks', 
        image: 'https://images.unsplash.com/photo-1531749668029-2db88e4276c7?w=500&auto=format&fit=crop&q=60', 
        price: 5.99,
        category: 'appetizers',
        description: 'Golden fried mozzarella sticks with marinara sauce',
        status: 'active'
      },
      { 
        name: 'Caesar Salad', 
        image: 'https://images.unsplash.com/photo-1546793665-c74683f339c1?w=500&auto=format&fit=crop&q=60', 
        price: 7.99,
        category: 'sides',
        description: 'Fresh romaine lettuce with caesar dressing',
        status: 'active'
      },
      { 
        name: 'Chocolate Brownie', 
        image: 'https://images.unsplash.com/photo-1564355808539-22fda35bed7e?w=500&auto=format&fit=crop&q=60', 
        price: 3.99,
        category: 'desserts',
        description: 'Warm chocolate brownie with vanilla ice cream',
        status: 'active'
      }
    ];

    console.log('🍔 Creating food items...');
    
    // Add some items with intentional price vulnerabilities for testing
    for (const food of foods) {
      // VULNERABILITY: Some items have manipulatable prices stored as strings
      if (Math.random() > 0.8) {
        food.cost_price = (food.price * 0.3).toFixed(2); // Hidden cost price
        food.supplier_info = 'Internal supplier data'; // Sensitive info
        food.internal_notes = 'Price can be modified via client-side manipulation'; // Internal notes
      }
    }
    
    await Food.bulkCreate(foods);
    console.log(`   ✓ ${foods.length} food items created`);

    // Create sample orders with new food items
    const orders = [
      { 
        items: JSON.stringify([
          { name: 'Margherita Pizza', price: 12.99, qty: 1 },
          { name: 'Soft Drinks (Regular)', price: 2.49, qty: 2 },
          { name: 'Classic Crispy Fries', price: 3.99, qty: 1 }
        ]), 
        totalAmount: 21.96, 
        status: 'pending', 
        userId: 1 
      },
      { 
        items: JSON.stringify([
          { name: 'Double Bacon Cheeseburger', price: 8.99, qty: 1 },
          { name: 'Loaded Cheese Fries', price: 5.99, qty: 1 },
          { name: 'Soft Drinks (Large)', price: 3.49, qty: 1 }
        ]), 
        totalAmount: 18.47, 
        status: 'preparing', 
        userId: 2 
      },
      { 
        items: JSON.stringify([
          { name: 'Crispy Fried Chicken (3pc)', price: 9.99, qty: 1 },
          { name: 'Buffalo Wings (6pc)', price: 7.99, qty: 1 },
          { name: 'Fresh Lemonade', price: 3.99, qty: 2 }
        ]), 
        totalAmount: 25.96, 
        status: 'delivered', 
        userId: 1 
      },
      { 
        items: JSON.stringify([
          { name: 'Classic Jollof Rice', price: 8.99, qty: 2 },
          { name: 'Grilled Chicken Wrap', price: 6.99, qty: 1 }
        ]), 
        totalAmount: 24.97, 
        status: 'ready', 
        userId: 3 
      }
    ];

    console.log('📦 Creating sample orders...');
    await Order.bulkCreate(orders);
    console.log(`   ✓ ${orders.length} orders created`);

    // Create sample complaints
    const complaints = [
      { 
        orderId: '1', 
        details: 'Pizza was cold when delivered, fries were soggy', 
        photo: null, 
        userId: 1 
      },
      { 
        orderId: '2', 
        details: 'Wrong order received - got chicken wings instead of burger', 
        photo: null, 
        userId: 2 
      },
      { 
        orderId: '3', 
        details: 'Delivery was 2 hours late and ice cream was melted', 
        photo: null, 
        userId: 1 
      },
      { 
        orderId: '4', 
        details: 'Jollof rice was too spicy and portion was small', 
        photo: null, 
        userId: 3 
      }
    ];

    console.log('💬 Creating complaints...');
    await Complaint.bulkCreate(complaints);
    console.log(`   ✓ ${complaints.length} complaints created`);

    // Create sample reviews with XSS vulnerabilities
    const reviews = [
      {
        foodId: 1, // Classic Crispy Fries
        userId: 1,
        rating: 5,
        title: 'Best fries in town!',
        comment: 'Perfectly crispy and salted. Always fresh and hot.',
        approved: true
      },
      {
        foodId: 13, // Classic Beef Burger
        userId: 2,
        rating: 4,
        title: 'Great burger, could use more sauce',
        comment: 'The patty is juicy and flavorful, but needs more special sauce.',
        approved: true
      },
      {
        foodId: 20, // Margherita Pizza
        userId: 3,
        rating: 5,
        title: 'Authentic Italian taste!',
        comment: 'Fresh mozzarella and basil make this pizza amazing.',
        approved: true
      },
      // VULNERABILITY: Reviews with potential XSS payloads (for testing)
      {
        foodId: 9, // Fried Chicken
        userId: 4,
        rating: 3,
        title: 'Decent chicken <script>console.log("XSS test")</script>',
        comment: 'The chicken was okay but <img src=x onerror="console.log(\'stored XSS\')"> a bit dry.',
        approved: false
      }
    ];

    console.log('⭐ Creating sample reviews...');
    await Review.bulkCreate(reviews);
    console.log(`   ✓ ${reviews.length} reviews created`);

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
        description: 'User input not properly sanitized in reviews and complaints',
        severity: 'medium',
        resolved: false,
        assignedTo: 3,
        flag: 'WeEat{XSS_R3v13w_F0rm}',
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
        description: 'Client-side price validation allows price tampering in cart',
        severity: 'critical',
        resolved: false,
        assignedTo: 4,
        flag: 'WeEat{Pr1c3_M4n1pul4t10n_C4rt}',
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
        flag: 'WeEat{SSRF_1m4g3_Pr0xy}',
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
      },
      {
        title: 'XXE Injection',
        description: 'XML parser accepts external entities',
        severity: 'high',
        resolved: false,
        assignedTo: 4,
        flag: 'WeEat{XXE_XML_P4rs3r}',
        found: false
      },
      {
        title: 'CSRF Attack Vector',
        description: 'No CSRF tokens on state-changing operations',
        severity: 'medium',
        resolved: false,
        assignedTo: 3,
        flag: 'WeEat{CSRF_N0_T0k3ns}',
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
    
    console.log('\n🍔 Menu Categories:');
    console.log('   - Mains: Burgers, Pizza, Chicken, Jollof Rice, Noodles, Wraps');
    console.log('   - Sides: Fries, Onion Rings, Salads');
    console.log('   - Appetizers: Wings, Mozzarella Sticks');
    console.log('   - Desserts: Ice Cream, Brownies');
    console.log('   - Beverages: Soft Drinks, Lemonade');
    
    console.log('\n🎯 Vulnerability Flags Created:');
    vulnerabilities.forEach((v, i) => {
      console.log(`   ${i + 1}. ${v.title} (${v.severity})`);
    });
    
    console.log('\n💰 Price Manipulation Attack Surface:');
    console.log('   - Client-side price validation in cart');
    console.log('   - Hidden discount codes (INTERNAL99, DEBUG100)');
    console.log('   - Bulk discount manipulation');
    console.log('   - Negative pricing with special headers');
    console.log('   - Staff/Admin pricing overrides');
    
    console.log('\n🚀 Start the app with: npm start');
    console.log('🌐 Visit: http://localhost:3000');
    
    process.exit(0);
  } catch (err) {
    console.error('❌ Seeding failed:', err);
    process.exit(1);
  }
})();
