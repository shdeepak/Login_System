const request = require('supertest');
const User = require('../../models/User');
const bcrypt = require('bcryptjs');

class TestHelpers {
  static async createTestUser(userData = {}) {
    const defaultUser = {
      username: 'testuser',
      email: 'test@example.com',
      password: await bcrypt.hash('TestPassword123!', 12),
      role: 'User'
    };
    
    const user = new User({ ...defaultUser, ...userData });
    return await user.save();
  }

  static async createTestAdmin(userData = {}) {
    const defaultAdmin = {
      username: 'testadmin',
      email: 'admin@example.com',
      password: await bcrypt.hash('AdminPassword123!', 12),
      role: 'Admin'
    };
    
    const admin = new User({ ...defaultAdmin, ...userData });
    return await admin.save();
  }

  static mockCaptcha() {
    // Mock fetch for CAPTCHA verification in tests
    global.fetch = jest.fn(() =>
      Promise.resolve({
        json: () => Promise.resolve({ success: true })
      })
    );
  }

  static mockCaptchaFailure() {
    global.fetch = jest.fn(() =>
      Promise.resolve({
        json: () => Promise.resolve({ 
          success: false, 
          'error-codes': ['invalid-input-response'] 
        })
      })
    );
  }

  static generateValidUserData() {
    const timestamp = Date.now();
    return {
      username: `user${timestamp}`,
      email: `user${timestamp}@example.com`,
      password: 'ValidPassword123!',
      role: 'User',
      captcha: 'mock-captcha-response'
    };
  }

  static generateInvalidUserData() {
    return [
      // Missing fields
      { username: '', email: 'test@example.com', password: 'ValidPassword123!' },
      { username: 'testuser', email: '', password: 'ValidPassword123!' },
      { username: 'testuser', email: 'test@example.com', password: '' },
      
      // Invalid formats
      { username: 'ab', email: 'test@example.com', password: 'ValidPassword123!' }, // Too short
      { username: 'testuser', email: 'invalid-email', password: 'ValidPassword123!' }, // Invalid email
      { username: 'testuser', email: 'test@example.com', password: 'weak' }, // Weak password
      
      // Invalid characters
      { username: 'test@user', email: 'test@example.com', password: 'ValidPassword123!' }, // Special chars in username
      { username: 'testuser', email: 'test@example.com', password: 'password' }, // Common password
    ];
  }
}

module.exports = TestHelpers;
