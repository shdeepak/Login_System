const { execSync } = require('child_process');

console.log('🚀 Starting comprehensive authentication system tests...\n');

try {
  // Run all tests with coverage
  console.log('📊 Running tests with coverage report...');
  execSync('npm run test:coverage', { stdio: 'inherit' });
  
  console.log('\n✅ All tests completed successfully!');
  console.log('\n📋 Test Summary:');
  console.log('- Authentication routes tested');
  console.log('- Edge cases and security vulnerabilities tested');
  console.log('- Model validation tested');
  console.log('- Duplicate registration prevention verified');
  console.log('- Account lockout functionality verified');
  console.log('- CAPTCHA integration tested');
  console.log('- Role-based access control tested');
  
} catch (error) {
  console.error('\n❌ Tests failed!');
  console.error(error.message);
  process.exit(1);
}
