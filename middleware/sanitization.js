const mongoSanitize = require('express-mongo-sanitize');

// Sanitize input data
const sanitizeInput = (req, res, next) => {
  // Remove any keys that start with '$' or contain '.'
  mongoSanitize.sanitize(req.body);
  mongoSanitize.sanitize(req.query);
  mongoSanitize.sanitize(req.params);
  
  // Additional custom sanitization
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        // Trim whitespace
        req.body[key] = req.body[key].trim();
        
        // Remove HTML tags (basic sanitization)
        req.body[key] = req.body[key].replace(/<[^>]*>/g, '');
      }
    });
  }
  
  next();
};

// XSS protection
const xssProtection = (req, res, next) => {
  // Set XSS protection headers
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  
  next();
};

module.exports = {
  sanitizeInput,
  xssProtection
};
