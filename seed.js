require('dotenv').config();
const { sequelize, User, Staff, Order, Complaint, Bug } = require('./models');

(async () => {
  try {
    // Sync database (force true will drop existing tables)
    await sequelize.sync({ force: true });
    console.log('Database synced and cleared!');

    // Seed Users
    const users = [
      { name: 'Alice Customer', email: 'alice@example.com', role: 'customer', password: 'alice123' },
      { name: 'Bob Customer', email: 'bob@example.com', role: 'customer', password: 'bob123' },
    ];
    for (const u of users) {
      const user = await User.create({ name: u.name, email: u.email, role: u.role, passwordHash: 'temp' });
      await user.setPassword(u.password);
      await user.save();
    }
    console.log('Seeded users.');

    // Seed Staff
    const staffs = [
      { name: 'Charlie Staff', email: 'charlie@weeat.com', role: 'staff', password: 'charlie123' },
      { name: 'Diana Admin', email: 'diana@weeat.com', role: 'admin', password: 'diana123' },
    ];
    for (const s of staffs) {
      const staff = await Staff.create({ name: s.name, email: s.email, role: s.role, passwordHash: 'temp' });
      await staff.setPassword(s.password);
      await staff.save();
    }
    console.log('Seeded staff.');

    // Seed Orders
    await Order.bulkCreate([
      { items: 'Pizza, Soda', totalAmount: 25.5, status: 'pending', userId: 1 },
      { items: 'Burger, Fries', totalAmount: 15.0, status: 'delivering', userId: 2 },
    ]);
    console.log('Seeded orders.');

    // Seed Complaints
    await Complaint.bulkCreate([
      { orderId: 'ORD001', details: 'Wrong item delivered', photo: null, userId: 1 },
      { orderId: 'ORD002', details: 'Late delivery', photo: null, userId: 2 },
    ]);
    console.log('Seeded complaints.');

    // Seed Bugs
    await Bug.bulkCreate([
      { title: 'XSS in order page', description: 'Found XSS when entering special characters in order form', severity: 'high', resolved: false, assignedTo: 2 },
      { title: 'SQLi in login', description: 'SQL injection possible via login email field', severity: 'critical', resolved: false, assignedTo: 2 },
    ]);
    console.log('Seeded bugs.');

    console.log('✅ Seeding complete!');
    process.exit(0);
  } catch (err) {
    console.error('Seeding failed:', err);
    process.exit(1);
  }
})();
