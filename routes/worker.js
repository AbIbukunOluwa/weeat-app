// const express = require('express');
// const router = express.Router();
// 
// // Worker dashboard
// router.get('/', (req, res) => {
//   res.render('worker/dashboard', { title: 'Worker Dashboard' });
// });
// 
// // Kitchen staff page
// router.get('/kitchen', (req, res) => {
//   res.render('worker/kitchen', { title: 'Kitchen Orders' });
// });
// 
// // Driver page
// router.get('/driver', (req, res) => {
//   res.render('worker/driver', { title: 'Driver Deliveries' });
// });
// 
// module.exports = router;
// First iteration


const express = require('express');
const router = express.Router();

// Worker portal landing
router.get('/', (req, res) => {
  res.render('worker', { title: 'Worker Portal' });
});

module.exports = router;
