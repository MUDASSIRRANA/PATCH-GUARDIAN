const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { spawn } = require('child_process');
require('dotenv').config();

// Debug logging for email configuration
console.log('Email Configuration Check:');
console.log('EMAIL_USER exists:', !!process.env.EMAIL_USER);
console.log('EMAIL_APP_PASSWORD exists:', !!process.env.EMAIL_APP_PASSWORD);
console.log('EMAIL_USER value:', process.env.EMAIL_USER ? process.env.EMAIL_USER : 'Not set');

const app = express();
const port = process.env.PORT || 3001;

// CORS configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:8080',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080'
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
app.use(express.json());

// MongoDB connection
console.log('Attempting to connect to MongoDB...');
console.log('Connection string:', process.env.MONGODB_URI ? 'Found' : 'Not found');

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('MongoDB connected successfully');
})
.catch((err) => {
  console.error('MongoDB connection error:', err);
  console.error('Error details:', err.message);
  process.exit(1);
});

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD
  },
  debug: true // Enable debug logging for nodemailer
});

// Verify email configuration
const verifyEmailConfig = async () => {
  try {
    console.log('Attempting to verify email configuration...');
    console.log('Using email:', process.env.EMAIL_USER);
    await transporter.verify();
    console.log('Email server connection verified successfully');
  } catch (error) {
    console.error('Email configuration error details:', {
      name: error.name,
      message: error.message,
      code: error.code,
      command: error.command,
      response: error.response
    });
    throw error;
  }
};

// Initialize email configuration
verifyEmailConfig().catch(console.error);

// Store verification tokens and attempts (in production, use Redis or similar)
const verificationTokens = new Map();
const verificationAttempts = new Map();

// Function to generate verification token
const generateVerificationToken = () => {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
};

// Function to track verification attempts
const trackVerificationAttempt = (email) => {
  const attempts = verificationAttempts.get(email) || 0;
  verificationAttempts.set(email, attempts + 1);
  return attempts + 1;
};

// Function to reset verification attempts
const resetVerificationAttempts = (email) => {
  verificationAttempts.delete(email);
};

// Function to check if account is blocked from verification
const isVerificationBlocked = (email) => {
  const attempts = verificationAttempts.get(email) || 0;
  return attempts >= 3;
};

// Function to send verification email
const sendVerificationEmail = async (email, token) => {
  console.log(`Attempting to send verification email to: ${email}`);
  
  const mailOptions = {
    from: {
      name: 'SecurePatcher Authentication',
      address: process.env.EMAIL_USER
    },
    to: email,
    subject: 'Your Login Verification Code',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2563eb; text-align: center;">Login Verification Code</h1>
        <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; text-align: center;">
          <p style="font-size: 16px; color: #374151;">Your verification code is:</p>
          <h2 style="font-size: 32px; letter-spacing: 4px; color: #1f2937; margin: 20px 0;">${token}</h2>
          <p style="color: #6b7280; font-size: 14px;">This code will expire in 10 minutes.</p>
        </div>
        <p style="color: #ef4444; font-size: 14px; text-align: center; margin-top: 20px;">
          If you didn't request this code, please ignore this email and make sure your account is secure.
        </p>
      </div>
    `
  };

  try {
    console.log('Email configuration:', {
      from: mailOptions.from,
      to: mailOptions.to,
      subject: mailOptions.subject
    });
    
    const info = await transporter.sendMail(mailOptions);
    console.log('Verification email sent successfully:', {
      messageId: info.messageId,
      response: info.response
    });
    return true;
  } catch (error) {
    console.error('Error sending verification email:', {
      name: error.name,
      message: error.message,
      code: error.code,
      command: error.command,
      response: error.response
    });
    return false;
  }
};

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date },
  isLocked: { 
    type: Boolean,
    default: false
  },
  verificationToken: String,
  verificationTokenExpires: Date,
  submittedCodes: [
    {
      code: String,
      submittedAt: { type: Date, default: Date.now },
      analysis: String // optional, can be filled later
    }
  ]
});

// Add methods to the user schema
userSchema.methods.incrementLoginAttempts = async function() {
  // Increment login attempts
  this.loginAttempts += 1;
  
  // Lock account if attempts exceed 3
  if (this.loginAttempts >= 3) {
    this.isLocked = true;
    this.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // Lock for 30 minutes
  }
  
  await this.save();
  return this.loginAttempts;
};

userSchema.methods.resetLoginAttempts = async function() {
  this.loginAttempts = 0;
  this.isLocked = false;
  this.lockUntil = undefined;
  await this.save();
};

const User = mongoose.model('User', userSchema);

// Encryption configuration
if (!process.env.ENCRYPTION_KEY || process.env.ENCRYPTION_KEY.length !== 32) {
  console.error('Invalid encryption key. Must be exactly 32 characters.');
  process.exit(1);
}

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Generate deterministic IV for email addresses
const generateEmailIV = (email) => {
  return crypto
    .createHash('sha256')
    .update(email)
    .digest()
    .slice(0, 16);
};

// Encrypt data with optional deterministic IV for emails
const encryptData = (data, isEmail = false) => {
  try {
    const iv = isEmail ? generateEmailIV(data) : crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Encryption failed');
  }
};

// Decrypt data
const decryptData = (data) => {
  try {
    const [ivHex, encryptedHex] = data.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Decryption failed');
  }
};

// Security Validation Functions
const securityValidation = {
  // Password requirements
  PASSWORD_MIN_LENGTH: 8,
  PASSWORD_REGEX: {
    uppercase: /[A-Z]/,
    lowercase: /[a-z]/,
    number: /[0-9]/,
    special: /[!@#$%^&*()_+\-=\[\]{};:,.<>?]/
  },
  
  // Email validation with strict regex
  EMAIL_REGEX: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  
  // Name validation
  NAME_MIN_LENGTH: 2,
  NAME_MAX_LENGTH: 50,
  NAME_REGEX: /^[a-zA-Z\s-']+$/,

  validatePassword(password) {
    const errors = [];
    
    if (!password || password.length < this.PASSWORD_MIN_LENGTH) {
      errors.push(`Password must be at least ${this.PASSWORD_MIN_LENGTH} characters long`);
    }
    
    if (!this.PASSWORD_REGEX.uppercase.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!this.PASSWORD_REGEX.lowercase.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!this.PASSWORD_REGEX.number.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (!this.PASSWORD_REGEX.special.test(password)) {
      errors.push('Password must contain at least one special character');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  },

  validateEmail(email) {
    const errors = [];
    
    if (!email) {
      errors.push('Email is required');
    } else if (!this.EMAIL_REGEX.test(email)) {
      errors.push('Invalid email format');
    }
    
    // Check for common security risks in email
    if (email && (
      email.includes('<script>') ||
      email.includes('</script>') ||
      email.includes('<iframe>') ||
      email.includes('javascript:')
    )) {
      errors.push('Email contains potentially malicious content');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  },

  validateName(name) {
    const errors = [];
    
    if (!name) {
      errors.push('Name is required');
    } else {
      if (name.length < this.NAME_MIN_LENGTH || name.length > this.NAME_MAX_LENGTH) {
        errors.push(`Name must be between ${this.NAME_MIN_LENGTH} and ${this.NAME_MAX_LENGTH} characters`);
      }
      
      if (!this.NAME_REGEX.test(name)) {
        errors.push('Name can only contain letters, spaces, hyphens, and apostrophes');
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  },

  sanitizeInput(input) {
    // Basic input sanitization
    return input
      .trim()
      .replace(/[<>]/g, '') // Remove < and > to prevent basic HTML injection
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }
};

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    console.log('Received registration request');
    const { name, email, password } = req.body;

    // Security validations
    const nameValidation = securityValidation.validateName(name);
    const emailValidation = securityValidation.validateEmail(email);
    const passwordValidation = securityValidation.validatePassword(password);

    // Collect all validation errors
    const validationErrors = [
      ...nameValidation.errors,
      ...emailValidation.errors,
      ...passwordValidation.errors
    ];

    if (validationErrors.length > 0) {
      console.log('Validation failed:', validationErrors);
      return res.status(400).json({ 
        error: 'Validation failed',
        details: validationErrors
      });
    }

    // Sanitize inputs
    const sanitizedName = securityValidation.sanitizeInput(name);
    const normalizedEmail = email.trim().toLowerCase();

    try {
      const encryptedEmail = encryptData(normalizedEmail, true);
      
      // Check if user already exists
      const existingUser = await User.findOne({ email: encryptedEmail });
      if (existingUser) {
        console.log('User already exists');
        return res.status(400).json({ error: 'User already exists' });
      }

      // Hash password with strong salt
      const hashedPassword = await bcrypt.hash(password, 12); // Increased from 10 to 12 rounds
      console.log('Password hashed successfully');

      // Encrypt sensitive data
      const encryptedName = encryptData(sanitizedName);
      console.log('User data encrypted successfully');

      // Create new user
      const user = new User({
        name: encryptedName,
        email: encryptedEmail,
        password: hashedPassword
      });

      await user.save();
      console.log('User saved to database');

      // Return success without exposing sensitive data
      res.status(201).json({ 
        message: 'User registered successfully',
        user: {
          name: sanitizedName,
          email: normalizedEmail
        }
      });
    } catch (dbError) {
      console.error('Database operation error:', dbError);
      throw dbError;
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint - First step (credentials verification)
app.post('/api/login', async (req, res) => {
  try {
    console.log('Login attempt received');
    const { email, password } = req.body;

    // Security validations
    const emailValidation = securityValidation.validateEmail(email);
    if (!emailValidation.isValid) {
      return res.status(400).json({ 
        error: 'Invalid email format',
        details: emailValidation.errors
      });
    }

    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    // Normalize and sanitize email
    const normalizedEmail = email.trim().toLowerCase();
    
    // Find user by encrypted email
    const encryptedEmail = encryptData(normalizedEmail, true);
    console.log('Looking for user with encrypted email');
    const user = await User.findOne({ email: encryptedEmail });
    
    if (!user) {
      // Use consistent timing to prevent timing attacks
      await bcrypt.compare(password, '$2a$12$' + 'a'.repeat(53));
      console.log('User not found');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (user.isLocked) {
      if (user.lockUntil && user.lockUntil > new Date()) {
        const remainingTime = Math.ceil((user.lockUntil.getTime() - Date.now()) / (60 * 1000));
        return res.status(423).json({ 
          error: 'Account locked',
          message: `Account is temporarily locked. Please try again in ${remainingTime} minutes.`,
          lockUntil: user.lockUntil
        });
      } else {
        await user.resetLoginAttempts();
      }
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      const attempts = await user.incrementLoginAttempts();
      const remainingAttempts = 3 - attempts;
      
      if (remainingAttempts <= 0) {
        return res.status(423).json({ 
          error: 'Account locked',
          message: 'Too many failed attempts. Account has been locked for 30 minutes.',
          lockUntil: user.lockUntil
        });
      }
      
      return res.status(401).json({ 
        error: 'Invalid credentials',
        remainingAttempts: remainingAttempts
      });
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();

    // Generate and send OTP
    const verificationToken = generateVerificationToken();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Store verification token
    verificationTokens.set(normalizedEmail, {
      token: verificationToken,
      expires: expiresAt
    });

    // Send verification email
    const emailSent = await sendVerificationEmail(normalizedEmail, verificationToken);
    if (!emailSent) {
      return res.status(500).json({ error: 'Failed to send verification email' });
    }

    // Generate temporary session token
    const tempToken = crypto.randomBytes(48).toString('hex');
    sessionTokens.set(tempToken, encryptedEmail);

    // Return success response with temporary token
    res.json({
      token: tempToken,
      message: 'Verification code sent to your email'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify token endpoint
app.post('/api/verify-token', async (req, res) => {
  try {
    const { email, token } = req.body;

    if (!email || !token) {
      return res.status(400).json({ error: 'Email and verification token are required' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check if account is blocked from verification
    if (isVerificationBlocked(normalizedEmail)) {
      return res.status(423).json({ 
        error: 'Account blocked',
        message: 'Too many failed verification attempts. Please try again later.',
        isBlocked: true
      });
    }

    const storedVerification = verificationTokens.get(normalizedEmail);

    if (!storedVerification) {
      trackVerificationAttempt(normalizedEmail);
      return res.status(401).json({ 
        error: 'Invalid or expired verification code',
        remainingAttempts: 3 - (verificationAttempts.get(normalizedEmail) || 0)
      });
    }

    if (new Date() > storedVerification.expires) {
      verificationTokens.delete(normalizedEmail);
      trackVerificationAttempt(normalizedEmail);
      return res.status(401).json({ 
        error: 'Verification code has expired',
        remainingAttempts: 3 - (verificationAttempts.get(normalizedEmail) || 0)
      });
    }

    if (token !== storedVerification.token) {
      const attempts = trackVerificationAttempt(normalizedEmail);
      const remainingAttempts = 3 - attempts;
      
      if (remainingAttempts <= 0) {
        return res.status(423).json({ 
          error: 'Account blocked',
          message: 'Too many failed verification attempts. Please try again later.',
          isBlocked: true
        });
      }

      return res.status(401).json({ 
        error: 'Invalid verification code',
        remainingAttempts
      });
    }

    // Find user and reset login attempts
    const encryptedEmail = encryptData(normalizedEmail, true);
    const user = await User.findOne({ email: encryptedEmail });
    await user.resetLoginAttempts();

    // Reset verification attempts on success
    resetVerificationAttempts(normalizedEmail);

    // Remove used token
    verificationTokens.delete(normalizedEmail);

    // Decrypt user data for response
    const decryptedName = decryptData(user.name);
    const decryptedEmail = decryptData(user.email);

    // Generate session token
    const sessionToken = crypto.randomBytes(48).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    sessionTokens.set(sessionToken, encryptedEmail);

    res.json({
      token: sessionToken,
      expiresAt,
      user: {
        name: decryptedName,
        email: decryptedEmail
      }
    });

  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const sessionTokens = new Map();


app.post('/api/submit-code', async (req, res) => {
  const { code, email } = req.body;
  if (!code || !email) {
    return res.status(400).json({ error: 'Email and code are required.' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const encryptedEmail = encryptData(normalizedEmail, true);
  const user = await User.findOne({ email: encryptedEmail });
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }
  user.submittedCodes.push({ code });
  await user.save();
  res.json({ message: 'Code submitted and saved successfully.' });
});

// POST /api/analyze-code
app.post('/api/analyze-code', (req, res) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.status(400).json({ error: 'No code provided' });
    }

    const py = spawn('python', ['vulnerability_analyzer.py']);

    let output = '';
    let error = '';

    py.stdout.on('data', (data) => { output += data.toString(); });
    py.stderr.on('data', (data) => { error += data.toString(); });

    py.stdin.write(code);
    py.stdin.end();

    py.on('close', (codeStatus) => {
      try {
        const result = JSON.parse(output);
        if (error) {
          console.warn('Analyzer stderr:', error);
        }
        res.json(result);
      } catch (e) {
        res.status(500).json({ error: error || 'Failed to parse analyzer output' });
      }
    });
  } catch (error) {
    console.error('Error analyzing code:', error);
    res.status(500).json({ error: 'Failed to analyze code' });
  }
});

// POST /api/patch/apply
// Invokes the Python patch generator located at backend-patch/mudassir/main.py
app.post('/api/patch/apply', (req, res) => {
  try {
    const vulnerability = req.body?.vulnerability;
    if (!vulnerability) {
      return res.status(400).json({ error: 'Missing vulnerability payload' });
    }

    // Resolve Python entry
    const scriptPath = require('path').join(__dirname, '..', 'backend-patch', 'mudassir', 'main.py');

    const py = spawn('python', [scriptPath]);

    let output = '';
    let error = '';

    py.stdout.on('data', (data) => { output += data.toString(); });
    py.stderr.on('data', (data) => { error += data.toString(); });

    // Send vulnerability context to the patch generator via stdin
    py.stdin.write(JSON.stringify({ vulnerability }));
    py.stdin.end();

    py.on('close', () => {
      if (error) {
        console.warn('Patch generator stderr:', error);
      }
      try {
        const result = JSON.parse(output);
        return res.json(result);
      } catch (e) {
        return res.status(500).json({ error: 'Failed to parse patch generator output', details: error || String(e) });
      }
    });
  } catch (e) {
    console.error('Patch apply error:', e);
    return res.status(500).json({ error: 'Failed to apply patch' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

function getAuthToken() {
  const sessionStr = localStorage.getItem('session');
  if (!sessionStr) return null;
  try {
    const session = JSON.parse(sessionStr);
    return session?.token || null;
  } catch {
    return null;
  }
} 