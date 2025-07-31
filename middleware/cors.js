const cors = require('cors');

const corsOptions = {
  origin: [
    'http://localhost:5000',
    'http://127.0.0.1:5000',
    'http://localhost:3000',
    'http://localhost:8080'
  ],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

const corsMiddleware = cors(corsOptions);

module.exports = {
  corsMiddleware,
  corsOptions
};
