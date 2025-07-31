const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Rate limiting
const createRateLimit = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
  });
};

// Different rate limits for different endpoints
const authLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  5, // limit each IP to 5 requests per windowMs
  'Too many authentication attempts, please try again later'
);

const generalLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  100, // limit each IP to 100 requests per windowMs
  'Too many requests from this IP, please try again later'
);

const securityMiddleware = {
  // Apply security headers
  helmet: helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
  }),
  
  // Prevent NoSQL injection attacks
  mongoSanitize: mongoSanitize({
    replaceWith: '_',
    onSanitize: ({ req, key }) => {
      console.warn(`Sanitized key: ${key} in request from IP: ${req.ip}`);
    },
  }),
  
  // Rate limiting
  authLimiter,
  generalLimiter,
};

module.exports = securityMiddleware;
