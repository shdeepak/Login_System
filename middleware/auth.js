const jwt = require('jsonwebtoken');

const authMiddleware = (roles = []) => {
  return (req, res, next) => {
    const authHeader = req.header('Authorization');
    const token = authHeader && authHeader.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      
      // Fixed: Changed &gt; to > and &amp;&amp; to &&
      if (roles.length > 0 && !roles.includes(decoded.role)) {
        return res.status(403).json({ error: 'Access denied. Insufficient privileges.' });
      }
      
      next();
    } catch (err) {
      console.error('Token verification error:', err);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
};

module.exports = authMiddleware;
