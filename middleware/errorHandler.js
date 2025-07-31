// Global error handler middleware
const errorHandler = (err, req, res, next) => {
  console.error('Global error:', err);
  
  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  // MongoDB duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern)[0];
    return res.status(400).json({
      error: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists`
    });
  }
  
  // Validation errors
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(error => error.message);
    return res.status(400).json({
      error: 'Validation failed',
      details: errors
    });
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'Token expired' });
  }
  
  // Default error response
  res.status(err.status || 500).json({
    error: 'Something went wrong',
    ...(isDevelopment && { 
      details: err.message,
      stack: err.stack 
    })
  });
};

// 404 handler for undefined routes
const notFoundHandler = (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method
  });
};

module.exports = {
  errorHandler,
  notFoundHandler
};
