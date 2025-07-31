const User = require('../../models/User');
const mongoose = require('mongoose');

describe('User Model', () => {
  describe('Validation', () => {
    it('should create a valid user', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'hashedpassword123',
        role: 'User'
      };

      const user = new User(userData);
      const savedUser = await user.save();

      expect(savedUser._id).toBeDefined();
      expect(savedUser.username).toBe(userData.username);
      expect(savedUser.email).toBe(userData.email);
      expect(savedUser.role).toBe(userData.role);
    });

    it('should require username', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'hashedpassword123'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow(/Username is required/);
    });

    it('should require email', async () => {
      const userData = {
        username: 'testuser',
        password: 'hashedpassword123'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow(/Email is required/);
    });

    it('should validate email format', async () => {
      const userData = {
        username: 'testuser',
        email: 'invalid-email',
        password: 'hashedpassword123'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow(/Please provide a valid email/);
    });

    it('should validate username length', async () => {
      const userData = {
        username: 'ab', // Too short
        email: 'test@example.com',
        password: 'hashedpassword123'
      };

      const user = new User(userData);
      
      await expect(user.save()).rejects.toThrow(/Username must be at least 3 characters/);
    });

    it('should enforce unique email constraint', async () => {
      const userData = {
        username: 'testuser1',
        email: 'test@example.com',
        password: 'hashedpassword123'
      };

      // Create first user
      const user1 = new User(userData);
      await user1.save();

      // Try to create second user with same email
      const user2 = new User({
        ...userData,
        username: 'testuser2'
      });

      await expect(user2.save()).rejects.toThrow(/duplicate key error/);
    });
  });

  describe('Account Lockout Methods', () => {
    let user;

    beforeEach(async () => {
      user = new User({
        username: 'testuser',
        email: 'test@example.com',
        password: 'hashedpassword123',
        role: 'User'
      });
      await user.save();
    });

    it('should increment login attempts', async () => {
      expect(user.failedLoginAttempts).toBe(0);
      
      await user.incrementLoginAttempts();
      await user.reload();
      
      expect(user.failedLoginAttempts).toBe(1);
    });

    it('should lock account after max attempts', async () => {
      // Increment to max attempts (5)
      for (let i = 0; i < 5; i++) {
        await user.incrementLoginAttempts();
        await user.reload();
      }
      
      expect(user.isLocked).toBe(true);
      expect(user.lockUntil).toBeDefined();
    });

    it('should reset login attempts', async () => {
      await user.incrementLoginAttempts();
      await user.incrementLoginAttempts();
      await user.reload();
      
      expect(user.failedLoginAttempts).toBe(2);
      
      await user.resetLoginAttempts();
      await user.reload();
      
      expect(user.failedLoginAttempts).toBeUndefined();
      expect(user.lockUntil).toBeUndefined();
    });
  });
});
