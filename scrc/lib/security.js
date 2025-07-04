import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { serialize, parse } from 'cookie';
import { RedisManager } from './redis.js';

// Security configuration
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

export class SecurityManager {
  // JWT Token Management
  static async generateTokens(userId, email, provider) {
    const sessionId = crypto.randomUUID();
    const tokenId = crypto.randomUUID();
    
    const payload = {
      userId,
      email,
      provider,
      iat: Math.floor(Date.now() / 1000),
      sessionId,
      tokenId
    };

    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });

    // Store session in Redis
    await RedisManager.setSession(sessionId, {
      userId,
      email,
      provider,
      createdAt: new Date().toISOString(),
      lastActivity: new Date().toISOString(),
      isActive: true
    });

    // Store refresh token in Redis
    await RedisManager.setRefreshToken(userId, tokenId, 604800); // 7 days

    return { accessToken, refreshToken, sessionId, tokenId };
  }

  static async verifyAccessToken(token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const session = await RedisManager.getSession(decoded.sessionId);
      
      if (!session || !session.isActive) {
        throw new Error('Session not found or inactive');
      }

      // Update last activity
      await RedisManager.updateSessionActivity(decoded.sessionId);

      return decoded;
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }

  static async verifyRefreshToken(token) {
    try {
      const decoded = jwt.verify(token, JWT_REFRESH_SECRET);
      
      // Check if refresh token exists in Redis
      const refreshTokenData = await RedisManager.getRefreshToken(decoded.userId, decoded.tokenId);
      if (!refreshTokenData || !refreshTokenData.isActive) {
        throw new Error('Refresh token not found or inactive');
      }

      return decoded;
    } catch (error) {
      throw new Error('Invalid or expired refresh token');
    }
  }

  static async revokeSession(sessionId) {
    await RedisManager.deleteSession(sessionId);
  }

  static async revokeRefreshToken(userId, tokenId) {
    await RedisManager.revokeRefreshToken(userId, tokenId);
  }

  // CSRF Protection
  static async generateCSRFToken(sessionId) {
    const token = crypto.randomBytes(32).toString('hex');
    await RedisManager.setCSRFToken(sessionId, token, 3600); // 1 hour
    return token;
  }

  static async validateCSRFToken(sessionId, token) {
    const storedTokenData = await RedisManager.getCSRFToken(sessionId);
    if (!storedTokenData || storedTokenData.token !== token) {
      return false;
    }
    
    const now = new Date();
    const expiresAt = new Date(storedTokenData.expiresAt);
    return now <= expiresAt;
  }

  // Rate Limiting
  static async checkRateLimit(identifier, maxAttempts = 5, windowMs = 900000) {
    const attempts = await RedisManager.addRateLimitAttempt(identifier, Math.floor(windowMs / 1000));
    
    if (attempts.length >= maxAttempts) {
      return {
        allowed: false,
        resetTime: new Date(attempts[0] + windowMs),
        attemptsRemaining: 0
      };
    }

    return {
      allowed: true,
      attemptsRemaining: maxAttempts - attempts.length,
      resetTime: new Date(Date.now() + windowMs)
    };
  }

  // Account Lockout
  static async checkAccountLockout(email) {
    const lockout = await RedisManager.getAccountLockout(email);
    if (lockout && lockout.lockedUntil && new Date() < new Date(lockout.lockedUntil)) {
      return {
        locked: true,
        lockedUntil: new Date(lockout.lockedUntil),
        reason: 'Too many failed login attempts'
      };
    }
    return { locked: false };
  }

  static async recordFailedLogin(email) {
    await RedisManager.recordFailedLogin(email);
  }

  static async clearFailedLogins(email) {
    await RedisManager.deleteAccountLockout(email);
  }

  // Password Security
  static async hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  }

  static async verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
  }

  static validatePasswordStrength(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    const errors = [];
    if (password.length < minLength) errors.push(`Password must be at least ${minLength} characters long`);
    if (!hasUpperCase) errors.push('Password must contain at least one uppercase letter');
    if (!hasLowerCase) errors.push('Password must contain at least one lowercase letter');
    if (!hasNumbers) errors.push('Password must contain at least one number');
    if (!hasSpecialChar) errors.push('Password must contain at least one special character');

    return {
      isValid: errors.length === 0,
      errors,
      strength: this.calculatePasswordStrength(password)
    };
  }

  static calculatePasswordStrength(password) {
    let score = 0;
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    if (password.length >= 16) score += 1;

    if (score < 3) return 'weak';
    if (score < 5) return 'medium';
    return 'strong';
  }

  // Cookie Management
  static createSecureCookie(name, value, options = {}) {
    const defaultOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 86400, // 24 hours
      path: '/'
    };

    return serialize(name, value, { ...defaultOptions, ...options });
  }

  static parseCookies(cookieHeader) {
    return cookieHeader ? parse(cookieHeader) : {};
  }

  // Input Sanitization
  static sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    
    return input
      .replace(/[<>]/g, '') // Remove potential HTML tags
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+=/gi, '') // Remove event handlers
      .trim();
  }

  // Security Headers
  static getSecurityHeaders() {
    return {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
    };
  }

  // Redis Health Check
  static async checkRedisHealth() {
    return await RedisManager.healthCheck();
  }

  // Cleanup expired data
  static async cleanupExpiredData() {
    await RedisManager.cleanupExpiredData();
  }
}