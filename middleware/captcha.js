const verifyCaptcha = async (req, res, next) => {
  const { captcha } = req.body;
  
  // Check if captcha response exists
  if (!captcha) {
    return res.status(400).json({ 
      error: 'CAPTCHA verification is required' 
    });
  }

  const secretKey = process.env.RECAPTCHA_SECRET_KEY;
  const verifyURL = 'https://www.google.com/recaptcha/api/siteverify';

  try {
    // Verify captcha with Google using built-in fetch
    const response = await fetch(verifyURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `secret=${secretKey}&response=${captcha}&remoteip=${req.ip}`
    });

    const data = await response.json();
    
    if (data.success) {
      console.log('CAPTCHA verified successfully');
      next();
    } else {
      console.log('CAPTCHA verification failed:', data['error-codes']);
      return res.status(400).json({ 
        error: 'CAPTCHA verification failed. Please try again.' 
      });
    }
  } catch (error) {
    console.error('CAPTCHA verification error:', error);
    return res.status(500).json({ 
      error: 'CAPTCHA verification service unavailable' 
    });
  }
};

module.exports = verifyCaptcha;
