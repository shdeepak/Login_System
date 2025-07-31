const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters long'],
    maxlength: [30, 'Username must not exceed 30 characters'],
    match: [/^[a-zA-Z0-9]+$/, 'Username must only contain alphanumeric characters'],
    index: true
  },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email'],
    index: true
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters long'],
    select: false
  },
  role: { 
    type: String, 
    enum: {
      values: ['Admin', 'User'],
      message: 'Role must be either Admin or User'
    },
    default: 'User'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date
  },
  // Account lockout fields
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date
  }
}, {
  timestamps: true,
  versionKey: false
});

// Constants for lockout mechanism
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes

// Virtual property to check if account is locked
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Instance method to increment login attempts
userSchema.methods.incrementLoginAttempts = async function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $set: { 
        failedLoginAttempts: 1 
      },
      $unset: { 
        lockUntil: 1 
      }
    });
  }
  
  // Otherwise increment the attempts
  const updates = { $inc: { failedLoginAttempts: 1 } };
  
  // Lock the account if we've reached max attempts and it's not locked already
  if (this.failedLoginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.isLocked) {
    updates.$set = { 
      lockUntil: Date.now() + LOCK_TIME 
    };
  }
  
  return this.updateOne(updates);
};

// Instance method to reset login attempts on successful login
userSchema.methods.resetLoginAttempts = async function() {
  return this.updateOne({
    $unset: { 
      failedLoginAttempts: 1, 
      lockUntil: 1 
    }
  });
};

// Static method for authentication with lockout handling
userSchema.statics.getAuthenticated = async function(email, password) {
  const user = await this.findOne({ 
    email: { $regex: new RegExp(`^${email}$`, 'i') }
  }).select('+password');
  
  if (!user) {
    return { user: null, reason: 'NOT_FOUND' };
  }
  
  // Check if account is locked
  if (user.isLocked) {
    // Increment attempts even if locked to extend lock if needed
    await user.incrementLoginAttempts();
    return { user: null, reason: 'MAX_ATTEMPTS' };
  }
  
  // Check password
  const isMatch = await bcrypt.compare(password, user.password);
  
  if (isMatch) {
    // Reset attempts on successful login
    if (user.failedLoginAttempts && !user.isLocked) {
      await user.resetLoginAttempts();
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    return { user, reason: 'SUCCESS' };
  } else {
    // Password didn't match, record failed attempt
    await user.incrementLoginAttempts();
    return { user: null, reason: 'PASSWORD_INCORRECT' };
  }
};

// Compound index for better query performance
userSchema.index({ email: 1, username: 1 });

module.exports = mongoose.model('User', userSchema);
