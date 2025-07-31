const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');
const verifyCaptcha = require('../middleware/captcha');

const router = express.Router();

// Login route with account lockout protection
router.post('/login', verifyCaptcha, async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check JWT_SECRET before using it
    if (!process.env.JWT_SECRET) {
      console.error('❌ JWT_SECRET is not defined');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // Use the new authentication method with lockout handling
    const result = await User.getAuthenticated(email, password);
    
    switch (result.reason) {
      case 'SUCCESS':
        // Create JWT token
        const tokenPayload = {
          userId: result.user._id,
          role: result.user.role,
          iat: Math.floor(Date.now() / 1000)
        };
        
        const token = jwt.sign(
          tokenPayload,
          process.env.JWT_SECRET,
          { 
            expiresIn: '24h',
            issuer: 'auth-system',
            audience: 'auth-users'
          }
        );
        
        console.log('Login successful for user:', result.user.email, 'Role:', result.user.role);

        res.json({ 
          message: 'Login successful',
          token, 
          userRole: result.user.role,
          username: result.user.username,
          userId: result.user._id.toString()
        });
        break;
        
      case 'NOT_FOUND':
      case 'PASSWORD_INCORRECT':
        // Don't reveal which reason to prevent user enumeration
        res.status(401).json({ 
          error: 'Invalid email or password. Please check your credentials and try again.' 
        });
        break;
        
      case 'MAX_ATTEMPTS':
        // Get user to check lock time remaining
        const lockedUser = await User.findOne({ 
          email: { $regex: new RegExp(`^${email}$`, 'i') }
        });
        
        if (lockedUser && lockedUser.lockUntil) {
          const remainingTime = Math.ceil((lockedUser.lockUntil - Date.now()) / (60 * 1000));
          res.status(423).json({ 
            error: `Account temporarily locked due to multiple failed login attempts. Please try again in ${remainingTime} minutes.`,
            lockUntil: lockedUser.lockUntil,
            remainingMinutes: remainingTime
          });
        } else {
          res.status(423).json({ 
            error: 'Account temporarily locked due to multiple failed login attempts. Please try again later.' 
          });
        }
        break;
        
      default:
        res.status(500).json({ error: 'An error occurred during login. Please try again.' });
    }
    
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// Register route (unchanged but included for completeness) 
router.post('/register', verifyCaptcha, async (req, res) => {
  const { username, email, password, role } = req.body;

  try {
    const existingUser = await User.findOne({ 
      $or: [
        { email: { $regex: new RegExp(`^${email}$`, 'i') } },
        { username: { $regex: new RegExp(`^${username}$`, 'i') } }
      ]
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        error: existingUser.email.toLowerCase() === email.toLowerCase() 
          ? 'Email already exists' 
          : 'Username already exists' 
      });
    }

    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    const user = new User({ 
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword, 
      role: role || 'User'
    });
    
    await user.save();

    res.status(201).json({ 
      message: 'User registered successfully',
      user: {
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
    
  } catch (err) {
    console.error('Registration error:', err);
    
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern)[0];
      return res.status(400).json({ 
        error: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists` 
      });
    }
    
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// Admin route for viewing locked accounts
router.get('/admin', authMiddleware(['Admin']), async (req, res) => {
  try {
    const users = await User.find({}, {
      password: 0,
      __v: 0
    }).sort({ createdAt: -1 });
    
    const sanitizedUsers = users.map(user => ({
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
      isActive: user.isActive,
      failedLoginAttempts: user.failedLoginAttempts || 0,
      isLocked: user.isLocked,
      lockUntil: user.lockUntil
    }));
    
    res.json(sanitizedUsers);
    
  } catch (err) {
    console.error('Admin route error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Admin route to unlock a user account
router.post('/admin/unlock/:userId', authMiddleware(['Admin']), async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await user.resetLoginAttempts();
    
    res.json({ 
      message: `Account for ${user.username} has been unlocked successfully` 
    });
    
  } catch (err) {
    console.error('Unlock user error:', err);
    res.status(500).json({ error: 'Failed to unlock user account' });
  }
});

// Verify route (unchanged)
router.get('/verify', authMiddleware(), async (req, res) => {
  try {
    const user = await User.findById(req.user.userId, {
      password: 0,
      __v: 0
    });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ 
      user: { 
        username: user.username, 
        role: user.role,
        email: user.email,
        userId: user._id
      } 
    });
    
  } catch (err) {
    console.error('Verify error:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
});

module.exports = router;
