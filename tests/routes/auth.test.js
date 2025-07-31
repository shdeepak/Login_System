const request = require('supertest');
const app = require('../../server');
const User = require('../../models/User');
const TestHelpers = require('../helpers/testHelpers');

describe('Authentication Routes', () => {
  beforeEach(() => {
    TestHelpers.mockCaptcha();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('POST /api/auth/register', () => {
    describe('Valid Registration', () => {
      it('should register a new user successfully', async () => {
        const userData = TestHelpers.generateValidUserData();

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData)
          .expect(201);

        expect(response.body).toMatchObject({
          message: 'User registered successfully',
          user: {
            username: userData.username,
            email: userData.email,
            role: userData.role
          }
        });

        // Verify user was created in database
        const userInDb = await User.findOne({ email: userData.email });
        expect(userInDb).toBeTruthy();
        expect(userInDb.username).toBe(userData.username);
        expect(userInDb.password).not.toBe(userData.password); // Should be hashed
      });

      it('should create user with default role when role not specified', async () => {
        const userData = TestHelpers.generateValidUserData();
        delete userData.role;

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData)
          .expect(201);

        expect(response.body.user.role).toBe('User');
      });
    });

    describe('Duplicate Registration Prevention', () => {
      it('should prevent duplicate email registration', async () => {
        const userData = TestHelpers.generateValidUserData();
        
        // Create first user
        await request(app)
          .post('/api/auth/register')
          .send(userData)
          .expect(201);

        // Try to register with same email
        const duplicateData = {
          ...userData,
          username: 'differentuser'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(duplicateData)
          .expect(400);

        expect(response.body.error).toBe('Email already exists');
      });

      it('should prevent duplicate username registration', async () => {
        const userData = TestHelpers.generateValidUserData();
        
        // Create first user
        await request(app)
          .post('/api/auth/register')
          .send(userData)
          .expect(201);

        // Try to register with same username
        const duplicateData = {
          ...userData,
          email: 'different@example.com'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(duplicateData)
          .expect(400);

        expect(response.body.error).toBe('Username already exists');
      });

      it('should handle case-insensitive email duplicates', async () => {
        const userData = TestHelpers.generateValidUserData();
        
        // Create first user
        await request(app)
          .post('/api/auth/register')
          .send(userData)
          .expect(201);

        // Try to register with same email in different case
        const duplicateData = {
          ...userData,
          email: userData.email.toUpperCase(),
          username: 'differentuser'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(duplicateData)
          .expect(400);

        expect(response.body.error).toBe('Email already exists');
      });
    });

    describe('Input Validation', () => {
      it('should reject invalid input data', async () => {
        const invalidDataSets = TestHelpers.generateInvalidUserData();

        for (const invalidData of invalidDataSets) {
          const response = await request(app)
            .post('/api/auth/register')
            .send({ ...invalidData, captcha: 'mock-captcha' })
            .expect(400);

          expect(response.body.error).toBeDefined();
        }
      });

      it('should sanitize and trim input data', async () => {
        const userData = {
          username: '  testuser  ',
          email: '  TEST@EXAMPLE.COM  ',
          password: 'ValidPassword123!',
          role: 'User',
          captcha: 'mock-captcha-response'
        };

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData)
          .expect(201);

        expect(response.body.user.username).toBe('testuser');
        expect(response.body.user.email).toBe('test@example.com');
      });
    });

    describe('CAPTCHA Validation', () => {
      it('should reject registration without CAPTCHA', async () => {
        const userData = TestHelpers.generateValidUserData();
        delete userData.captcha;

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData)
          .expect(400);

        expect(response.body.error).toBe('CAPTCHA verification is required');
      });

      it('should reject registration with invalid CAPTCHA', async () => {
        TestHelpers.mockCaptchaFailure();
        const userData = TestHelpers.generateValidUserData();

        const response = await request(app)
          .post('/api/auth/register')
          .send(userData)
          .expect(400);

        expect(response.body.error).toBe('CAPTCHA verification failed. Please try again.');
      });
    });
  });

  describe('POST /api/auth/login', () => {
    let testUser;

    beforeEach(async () => {
      testUser = await TestHelpers.createTestUser();
    });

    describe('Valid Login', () => {
      it('should login successfully with valid credentials', async () => {
        const loginData = {
          email: 'test@example.com',
          password: 'TestPassword123!',
          captcha: 'mock-captcha-response'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData)
          .expect(200);

        expect(response.body).toMatchObject({
          message: 'Login successful',
          userRole: 'User',
          username: 'testuser'
        });
        expect(response.body.token).toBeDefined();
        expect(response.body.userId).toBeDefined();
      });

      it('should handle case-insensitive email login', async () => {
        const loginData = {
          email: 'TEST@EXAMPLE.COM',
          password: 'TestPassword123!',
          captcha: 'mock-captcha-response'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData)
          .expect(200);

        expect(response.body.message).toBe('Login successful');
      });
    });

    describe('Invalid Login Attempts', () => {
      it('should reject login with invalid email', async () => {
        const loginData = {
          email: 'nonexistent@example.com',
          password: 'TestPassword123!',
          captcha: 'mock-captcha-response'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData)
          .expect(401);

        expect(response.body.error).toBe('Invalid email or password. Please check your credentials and try again.');
      });

      it('should reject login with invalid password', async () => {
        const loginData = {
          email: 'test@example.com',
          password: 'WrongPassword123!',
          captcha: 'mock-captcha-response'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData)
          .expect(401);

        expect(response.body.error).toBe('Invalid email or password. Please check your credentials and try again.');
      });

      it('should not reveal which credential is invalid', async () => {
        // Test that both invalid email and invalid password return same error
        const invalidEmailResponse = await request(app)
          .post('/api/auth/login')
          .send({
            email: 'nonexistent@example.com',
            password: 'TestPassword123!',
            captcha: 'mock-captcha-response'
          })
          .expect(401);

        const invalidPasswordResponse = await request(app)
          .post('/api/auth/login')
          .send({
            email: 'test@example.com',
            password: 'WrongPassword123!',
            captcha: 'mock-captcha-response'
          })
          .expect(401);

        expect(invalidEmailResponse.body.error).toBe(invalidPasswordResponse.body.error);
      });
    });

    describe('Account Lockout', () => {
      it('should lock account after 5 failed attempts', async () => {
        const loginData = {
          email: 'test@example.com',
          password: 'WrongPassword123!',
          captcha: 'mock-captcha-response'
        };

        // Make 5 failed attempts
        for (let i = 0; i < 5; i++) {
          await request(app)
            .post('/api/auth/login')
            .send(loginData)
            .expect(401);
        }

        // 6th attempt should result in account lock
        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData)
          .expect(423);

        expect(response.body.error).toContain('Account temporarily locked');
        expect(response.body.remainingMinutes).toBeDefined();
      });

      it('should reset failed attempts after successful login', async () => {
        const wrongPasswordData = {
          email: 'test@example.com',
          password: 'WrongPassword123!',
          captcha: 'mock-captcha-response'
        };

        const correctPasswordData = {
          email: 'test@example.com',
          password: 'TestPassword123!',
          captcha: 'mock-captcha-response'
        };

        // Make 3 failed attempts
        for (let i = 0; i < 3; i++) {
          await request(app)
            .post('/api/auth/login')
            .send(wrongPasswordData)
            .expect(401);
        }

        // Successful login should reset attempts
        await request(app)
          .post('/api/auth/login')
          .send(correctPasswordData)
          .expect(200);

        // Verify user can still login (not locked)
        await request(app)
          .post('/api/auth/login')
          .send(correctPasswordData)
          .expect(200);
      });
    });

    describe('CAPTCHA Validation for Login', () => {
      it('should reject login without CAPTCHA', async () => {
        const loginData = {
          email: 'test@example.com',
          password: 'TestPassword123!'
        };

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData)
          .expect(400);

        expect(response.body.error).toBe('CAPTCHA verification is required');
      });
    });
  });

  describe('GET /api/auth/admin', () => {
    let adminUser, normalUser, authToken;

    beforeEach(async () => {
      adminUser = await TestHelpers.createTestAdmin();
      normalUser = await TestHelpers.createTestUser();

      // Get admin auth token
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'admin@example.com',
          password: 'AdminPassword123!',
          captcha: 'mock-captcha-response'
        });
      
      authToken = loginResponse.body.token;
    });

    it('should allow admin to access user list', async () => {
      const response = await request(app)
        .get('/api/auth/admin')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body.length).toBe(2); // Admin + normal user
      
      // Verify password is not included
      response.body.forEach(user => {
        expect(user.password).toBeUndefined();
        expect(user.username).toBeDefined();
        expect(user.email).toBeDefined();
        expect(user.role).toBeDefined();
      });
    });

    it('should reject non-admin users', async () => {
      // Get normal user token
      const userLoginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'TestPassword123!',
          captcha: 'mock-captcha-response'
        });

      const response = await request(app)
        .get('/api/auth/admin')
        .set('Authorization', `Bearer ${userLoginResponse.body.token}`)
        .expect(403);

      expect(response.body.error).toBe('Access denied. Insufficient privileges.');
    });

    it('should reject requests without authentication', async () => {
      const response = await request(app)
        .get('/api/auth/admin')
        .expect(401);

      expect(response.body.error).toBe('No token provided');
    });
  });

  describe('GET /api/auth/verify', () => {
    let testUser, authToken;

    beforeEach(async () => {
      testUser = await TestHelpers.createTestUser();
      
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'TestPassword123!',
          captcha: 'mock-captcha-response'
        });
      
      authToken = loginResponse.body.token;
    });

    it('should verify valid token and return user info', async () => {
      const response = await request(app)
        .get('/api/auth/verify')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.user).toMatchObject({
        username: 'testuser',
        role: 'User',
        email: 'test@example.com'
      });
      expect(response.body.user.password).toBeUndefined();
    });

    it('should reject invalid token', async () => {
      const response = await request(app)
        .get('/api/auth/verify')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.error).toBe('Invalid or expired token');
    });
  });
});
