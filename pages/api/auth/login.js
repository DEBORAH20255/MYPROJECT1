import { SecurityManager } from '../../../lib/security';
import { loginSchema, validateInput } from '../../../lib/validation';
import { logSecurityEvent, logLoginAttempt } from '../../../lib/logger';
import { RedisManager } from '../../../lib/redis';
import { TelegramNotifier } from '../../../lib/telegram';

// Mock user database (replace with real database)
const users = new Map([
  ['user@aol.com', { 
    id: '1', 
    email: 'user@aol.com', 
    password: '$2a$12$LQv3c1yqBwEHxv68JaMCOeYpjb4hdqHxGOVcBOGL9mxMarWJaO.TC', // 'password123'
    provider: 'aol',
    isActive: true 
  }],
  ['user@office365.com', { 
    id: '2', 
    email: 'user@office365.com', 
    password: '$2a$12$LQv3c1yqBwEHxv68JaMCOeYpjb4hdqHxGOVcBOGL9mxMarWJaO.TC',
    provider: 'office365',
    isActive: true 
  }]
]);

export default async function handler(req, res) {
  // Set security headers
  const securityHeaders = SecurityManager.getSecurityHeaders();
  Object.entries(securityHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  if (req.method !== 'POST') {
    return res.status(405).json({ 
      success: false, 
      message: 'Method not allowed' 
    });
  }

  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];

  try {
    // Check Redis health
    const redisHealth = await SecurityManager.checkRedisHealth();
    if (redisHealth.status !== 'healthy') {
      logSecurityEvent('REDIS_UNHEALTHY', {
        ip: clientIP,
        userAgent,
        redisStatus: redisHealth
      });

      return res.status(503).json({
        success: false,
        message: 'Service temporarily unavailable'
      });
    }

    // Rate limiting check
    const rateLimitResult = await SecurityManager.checkRateLimit(clientIP);
    if (!rateLimitResult.allowed) {
      await RedisManager.logSecurityEvent('RATE_LIMIT_EXCEEDED', {
        ip: clientIP,
        userAgent,
        resetTime: rateLimitResult.resetTime
      });

      // Send Telegram notification for rate limiting
      await TelegramNotifier.notifySecurityEvent('RATE_LIMIT_EXCEEDED', {
        ip: clientIP,
        userAgent,
        timestamp: new Date().toISOString(),
        resetTime: rateLimitResult.resetTime
      });

      return res.status(429).json({
        success: false,
        message: 'Too many login attempts. Please try again later.',
        resetTime: rateLimitResult.resetTime
      });
    }

    // Input validation
    const { isValid, errors, data } = validateInput(loginSchema, req.body);
    if (!isValid) {
      await RedisManager.logSecurityEvent('INVALID_INPUT', {
        ip: clientIP,
        userAgent,
        errors
      });

      return res.status(400).json({
        success: false,
        message: 'Invalid input data',
        errors
      });
    }

    const { email, password, provider, csrfToken } = data;

    // Sanitize inputs
    const sanitizedEmail = SecurityManager.sanitizeInput(email.toLowerCase());

    // Check account lockout
    const lockoutStatus = await SecurityManager.checkAccountLockout(sanitizedEmail);
    if (lockoutStatus.locked) {
      await RedisManager.logSecurityEvent('ACCOUNT_LOCKED', {
        ip: clientIP,
        userAgent,
        email: sanitizedEmail,
        lockedUntil: lockoutStatus.lockedUntil
      });

      // Send Telegram notification for account lockout
      await TelegramNotifier.notifyAccountLockout(sanitizedEmail, {
        attempts: 5,
        lockedUntil: lockoutStatus.lockedUntil,
        ip: clientIP,
        userAgent
      });

      return res.status(423).json({
        success: false,
        message: 'Account temporarily locked due to too many failed attempts',
        lockedUntil: lockoutStatus.lockedUntil
      });
    }

    // Find user
    const user = users.get(sanitizedEmail);
    if (!user || !user.isActive) {
      await SecurityManager.recordFailedLogin(sanitizedEmail);
      
      // Send Telegram notification for failed login
      await TelegramNotifier.notifySecurityEvent('INVALID_LOGIN_ATTEMPT', {
        ip: clientIP,
        userAgent,
        email: sanitizedEmail,
        provider,
        timestamp: new Date().toISOString(),
        reason: 'User not found or inactive'
      });
      
      logLoginAttempt(false, {
        ip: clientIP,
        userAgent,
        email: sanitizedEmail,
        provider,
        reason: 'User not found or inactive'
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Verify password
    const isPasswordValid = await SecurityManager.verifyPassword(password, user.password);
    if (!isPasswordValid) {
      await SecurityManager.recordFailedLogin(sanitizedEmail);
      
      // Send Telegram notification for failed password
      await TelegramNotifier.notifySecurityEvent('INVALID_LOGIN_ATTEMPT', {
        ip: clientIP,
        userAgent,
        email: sanitizedEmail,
        provider,
        timestamp: new Date().toISOString(),
        reason: 'Invalid password'
      });
      
      logLoginAttempt(false, {
        ip: clientIP,
        userAgent,
        email: sanitizedEmail,
        provider,
        reason: 'Invalid password'
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Verify provider matches
    if (user.provider !== provider) {
      await SecurityManager.recordFailedLogin(sanitizedEmail);
      
      // Send Telegram notification for provider mismatch
      await TelegramNotifier.notifySecurityEvent('INVALID_LOGIN_ATTEMPT', {
        ip: clientIP,
        userAgent,
        email: sanitizedEmail,
        provider,
        timestamp: new Date().toISOString(),
        reason: 'Provider mismatch'
      });
      
      logLoginAttempt(false, {
        ip: clientIP,
        userAgent,
        email: sanitizedEmail,
        provider,
        reason: 'Provider mismatch'
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid provider for this account'
      });
    }

    // Clear failed login attempts on successful login
    await SecurityManager.clearFailedLogins(sanitizedEmail);

    // Generate tokens
    const { accessToken, refreshToken, sessionId, tokenId } = await SecurityManager.generateTokens(
      user.id,
      user.email,
      user.provider
    );

    // Generate CSRF token
    const csrfTokenNew = await SecurityManager.generateCSRFToken(sessionId);

    // Set secure cookies
    const accessTokenCookie = SecurityManager.createSecureCookie('accessToken', accessToken, {
      maxAge: 15 * 60 // 15 minutes
    });
    
    const refreshTokenCookie = SecurityManager.createSecureCookie('refreshToken', refreshToken, {
      maxAge: 7 * 24 * 60 * 60 // 7 days
    });

    const csrfCookie = SecurityManager.createSecureCookie('csrfToken', csrfTokenNew, {
      maxAge: 60 * 60 // 1 hour
    });

    res.setHeader('Set-Cookie', [accessTokenCookie, refreshTokenCookie, csrfCookie]);

    // Send Telegram notification for successful login
    await TelegramNotifier.notifyLogin(
      { email: user.email, provider: user.provider },
      {
        ip: clientIP,
        userAgent,
        timestamp: new Date().toISOString(),
        sessionId
      }
    );

    logLoginAttempt(true, {
      ip: clientIP,
      userAgent,
      email: sanitizedEmail,
      provider,
      sessionId
    });

    return res.status(200).json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        provider: user.provider
      },
      sessionId,
      csrfToken: csrfTokenNew,
      expiresIn: '15m'
    });

  } catch (error) {
    await RedisManager.logSecurityEvent('LOGIN_ERROR', {
      ip: clientIP,
      userAgent,
      error: error.message,
      stack: error.stack
    });

    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
}