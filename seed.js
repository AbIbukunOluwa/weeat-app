require('dotenv').config();
const { sequelize, User, Order, Complaint, Vulnerability } = require('./models');

(async () => {
  try {
    await sequelize.sync({ force: true });
    console.log('Database synced and cleared!');

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

    await Order.bulkCreate([
      { items: 'Pizza, Soda', totalAmount: 25.5, status: 'pending', userId: 1 },
      { items: 'Burger, Fries', totalAmount: 15.0, status: 'delivering', userId: 2 }
    ]);

    await Complaint.bulkCreate([
      { orderId: 1, details: 'Wrong item delivered', photo: null, userId: 1 },
      { orderId: 2, details: 'Late delivery', photo: null, userId: 2 }
    ]);

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
