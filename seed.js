require('dotenv').config();
const { sequelize, User, Order, Complaint, Vulnerability, Food } = require('./models');

(async () => {
  try {
    await sequelize.sync({ force: true });
    console.log('Database synced and cleared!');

    // Users
    const users = [
      { name: 'Alice Customer', username: 'alice', email: 'alice@example.com', role: 'customer', password: 'alice123' },
      { name: 'Bob Customer', username: 'bob', email: 'bob@example.com', role: 'customer', password: 'bob123' },
      { name: 'Charlie Staff', username: 'charlie', email: 'charlie@weeat.com', role: 'staff', password: 'charlie123' },
      { name: 'Diana Admin', username: 'diana', email: 'diana@weeat.com', role: 'admin', password: 'diana123' }
    ];

    for (const u of users) {
      const user = await User.create({ name: u.name, username: u.username, email: u.email, passwordHash: 'temp', role: u.role });
      await user.setPassword(u.password);
      await user.save();
    }

    // Foods
    const foods = [
      { name: 'Fries', image: 'https://images.unsplash.com/photo-1541592106381-b31e9677c0e5?w=500', price: 3.5 },
      { name: 'Ice Cream', image: 'https://images.unsplash.com/photo-1580915411954-282cb1b0d780?w=500', price: 2.5 },
      { name: 'Jollof Rice', image: 'https://plus.unsplash.com/premium_photo-1694141252774-c937d97641da?w=500', price: 7.0 },
      { name: 'Noodles', image: 'https://images.unsplash.com/photo-1612929633738-8fe44f7ec841?w=500', price: 6.0 },
      { name: 'Fried Chicken', image: 'https://images.unsplash.com/photo-1626645738196-c2a7c87a8f58?w=500', price: 8.0 },
      { name: 'Wings', image: 'https://plus.unsplash.com/premium_photo-1672498193267-4f0e8c819bc8?w=500', price: 7.5 },
      { name: 'Burger', image: 'https://images.unsplash.com/photo-1667329829058-ac191ba4a905?w=500', price: 5.5 },
      { name: 'Wraps', image: 'https://plus.unsplash.com/premium_photo-1678051305065-1cd54b84272e?w=500', price: 6.5 },
      { name: 'Drinks', image: 'https://images.unsplash.com/photo-1630979805425-08f5f5f39aff?w=500', price: 2.0 },
      { name: 'Pizza', image: 'https://plus.unsplash.com/premium_photo-1667682942148-a0c98d1d70db?w=500', price: 9.0 }
    ];

    await Food.bulkCreate(foods);

    // Orders
    await Order.bulkCreate([
      { items: 'Pizza, Soda', totalAmount: 25.5, status: 'pending', userId: 1 },
      { items: 'Burger, Fries', totalAmount: 15.0, status: 'delivering', userId: 2 }
    ]);

    // Complaints
    await Complaint.bulkCreate([
      { orderId: 1, details: 'Wrong item delivered', photo: null, userId: 1 },
      { orderId: 2, details: 'Late delivery', photo: null, userId: 2 }
    ]);

    // Vulnerabilities
    await Vulnerability.bulkCreate([
      { title: 'XSS in order page', description: 'Reflected XSS on order input', severity: 'high', resolved: false, assignedTo: 3 },
      { title: 'SQLi in login', description: 'SQL injection via email field', severity: 'critical', resolved: false, assignedTo: 4 }
    ]);

    console.log('✅ Seeding complete!');
    process.exit(0);
  } catch (err) {
    console.error('Seeding failed:', err);
    process.exit(1);
  }
})();
