const request = require('supertest');
const app = require('../../server');
const User = require('../../models/User');
const TestHelpers = require('../helpers/testHelpers');

describe('Edge Cases and Security Tests', () => {
  beforeEach(() => {
    TestHelpers.mockCaptcha();
  });

  describe('Input Sanitization', () => {
    it('should handle SQL injection attempts', async () => {
      const maliciousData = {
        username: "admin'; DROP TABLE users; --",
        email: 'test@example.com',
        password: 'ValidPassword123!',
        role: 'User',
        captcha: 'mock-captcha-response'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(maliciousData)
        .expect(400);

      expect(response.body.error).toBeDefined();
    });

    it('should handle XSS attempts', async () => {
      const maliciousData = {
        username: '<script>alert("xss")</script>',
        email: 'test@example.com',
        password: 'ValidPassword123!',
        role: 'User',
        captcha: 'mock-captcha-response'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(maliciousData)
        .expect(400);

      expect(response.body.error).toBeDefined();
    });

    it('should handle extremely long input strings', async () => {
      const longString = 'a'.repeat(1000);
      const maliciousData = {
        username: longString,
        email: 'test@example.com',
        password: 'ValidPassword123!',
        role: 'User',
        captcha: 'mock-captcha-response'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(maliciousData)
        .expect(400);

      expect(response.body.error).toBeDefined();
    });
  });

  describe('Special Characters and Unicode', () => {
    it('should handle unicode characters in username', async () => {
      const unicodeData = {
        username: 'test用户',
        email: 'test@example.com',
        password: 'ValidPassword123!',
        role: 'User',
        captcha: 'mock-captcha-response'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(unicodeData)
        .expect(400);

      expect(response.body.error).toBeDefined();
    });

    it('should handle special email formats', async () => {
      const specialEmails = [
        'test+tag@example.com',
        'test.name@example.com',
        'test_name@example.com',
        'test-name@example.com'
      ];

      for (const email of specialEmails) {
        const userData = {
          username: `user${Date.now()}`,
          email: email,
          password: 'ValidPassword123!',
          role: 'User',
          captcha: 'mock-captcha-response'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData)
          .expect(201);

        expect(response.body.user.email).toBe(email.toLowerCase());
      }
    });
  });

  describe('Concurrent Registration Attempts', () => {
    it('should handle simultaneous registration with same email', async () => {
      const userData = TestHelpers.generateValidUserData();
      
      // Make concurrent requests
      const promises = Array(5).fill(null).map(() =>
        request(app)
          .post('/api/auth/register')
          .send(userData)
      );

      const responses = await Promise.all(promises);
      
      // Only one should succeed
      const successfulResponses = responses.filter(res => res.status === 201);
      const failedResponses = responses.filter(res => res.status === 400);
      
      expect(successfulResponses.length).toBe(1);
      expect(failedResponses.length).toBe(4);
    });
  });

  describe('Database Error Handling', () => {
    it('should handle database connection errors gracefully', async () => {
      // Temporarily close database connection
      await require('mongoose').disconnect();
      
      const userData = TestHelpers.generateValidUserData();
      
      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(500);

      expect(response.body.error).toBeDefined();
      
      // Reconnect for other tests
      const { MongoMemoryServer } = require('mongodb-memory-server');
      const mongoServer = await MongoMemoryServer.create();
      await require('mongoose').connect(mongoServer.getUri());
    });
  });

  describe('Rate Limiting Tests', () => {
    it('should enforce rate limiting on registration', async () => {
      const userData = TestHelpers.generateValidUserData();
      
      // Make multiple rapid requests
      const promises = Array(10).fill(null).map((_, index) =>
        request(app)
          .post('/api/auth/register')
          .send({
            ...userData,
            username: `user${index}`,
            email: `user${index}@example.com`
          })
      );

      const responses = await Promise.all(promises);
      
      // Some requests should be rate limited
      const rateLimitedResponses = responses.filter(res => res.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });
  });
});
