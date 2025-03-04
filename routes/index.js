const userRoutes = require('./userRoutes');
const authRoutes = require('./authRoutes');
const bookingRoutes = require('./bookingsRoutes');
const contractsRoutes = require('./contractsRoutes');
const invoicesRoutes = require('./invoicesRoutes');
const automatedInvoiceRoutes = require('./automatedInvoiceRoutes');
const automatedContractsRoutes = require('./automatedContractsRoutes');
const blogRoutes = require('./blogRoutes');
const subscriberRoutes = require('./subscriberRoute');
const eventRoutes = require('./eventsRoutes');
const analytics = require('./analyticsRoutes');

module.exports = {
  userRoutes,
  bookingRoutes,
  authRoutes,
  contractsRoutes,
  invoicesRoutes,
  automatedInvoiceRoutes,
  automatedContractsRoutes,
  blogRoutes,
  subscriberRoutes,
  eventRoutes,
  analyticsRoutes,
};
