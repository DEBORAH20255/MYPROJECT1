import { Redis } from '@upstash/redis';

// Initialize Upstash Redis client
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

export class RedisManager {
  // Session Management
  static async setSession(sessionId, sessionData, expirationSeconds = 86400) {
    const key = `session:${sessionId}`;
    await redis.setex(key, expirationSeconds, JSON.stringify(sessionData));
  }

  static async getSession(sessionId) {
    const key = `session:${sessionId}`;
    const data = await redis.get(key);
    return data ? JSON.parse(data) : null;
  }

  static async deleteSession(sessionId) {
    const key = `session:${sessionId}`;
    await redis.del(key);
  }

  static async updateSessionActivity(sessionId) {
    const key = `session:${sessionId}`;
    const session = await this.getSession(sessionId);
    if (session) {
      session.lastActivity = new Date().toISOString();
      await redis.setex(key, 86400, JSON.stringify(session)); // Reset TTL to 24 hours
    }
  }

  // CSRF Token Management
  static async setCSRFToken(sessionId, token, expirationSeconds = 3600) {
    const key = `csrf:${sessionId}`;
    const tokenData = {
      token,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expirationSeconds * 1000).toISOString()
    };
    await redis.setex(key, expirationSeconds, JSON.stringify(tokenData));
  }

  static async getCSRFToken(sessionId) {
    const key = `csrf:${sessionId}`;
    const data = await redis.get(key);
    return data ? JSON.parse(data) : null;
  }

  static async deleteCSRFToken(sessionId) {
    const key = `csrf:${sessionId}`;
    await redis.del(key);
  }

  // Rate Limiting
  static async getRateLimitAttempts(identifier) {
    const key = `ratelimit:${identifier}`;
    const data = await redis.get(key);
    return data ? JSON.parse(data) : [];
  }

  static async setRateLimitAttempts(identifier, attempts, expirationSeconds = 900) {
    const key = `ratelimit:${identifier}`;
    await redis.setex(key, expirationSeconds, JSON.stringify(attempts));
  }

  static async addRateLimitAttempt(identifier, expirationSeconds = 900) {
    const key = `ratelimit:${identifier}`;
    const now = Date.now();
    const attempts = await this.getRateLimitAttempts(identifier);
    
    // Remove old attempts outside the window
    const windowMs = expirationSeconds * 1000;
    const recentAttempts = attempts.filter(timestamp => now - timestamp < windowMs);
    
    // Add current attempt
    recentAttempts.push(now);
    
    await this.setRateLimitAttempts(identifier, recentAttempts, expirationSeconds);
    return recentAttempts;
  }

  // Account Lockout
  static async getAccountLockout(email) {
    const key = `lockout:${email}`;
    const data = await redis.get(key);
    return data ? JSON.parse(data) : null;
  }

  static async setAccountLockout(email, lockoutData, expirationSeconds = 1800) {
    const key = `lockout:${email}`;
    await redis.setex(key, expirationSeconds, JSON.stringify(lockoutData));
  }

  static async deleteAccountLockout(email) {
    const key = `lockout:${email}`;
    await redis.del(key);
  }

  static async recordFailedLogin(email) {
    const now = new Date();
    const lockout = await this.getAccountLockout(email) || { 
      attempts: 0, 
      firstAttempt: now.toISOString() 
    };
    
    lockout.attempts += 1;
    lockout.lastAttempt = now.toISOString();

    // Lock account after 5 failed attempts within 15 minutes
    const firstAttemptTime = new Date(lockout.firstAttempt);
    if (lockout.attempts >= 5 && (now - firstAttemptTime) < 900000) {
      lockout.lockedUntil = new Date(now.getTime() + 1800000).toISOString(); // 30 minutes
      await this.setAccountLockout(email, lockout, 1800); // 30 minutes TTL
    } else if ((now - firstAttemptTime) > 900000) {
      // Reset counter if attempts are spread over more than 15 minutes
      lockout.attempts = 1;
      lockout.firstAttempt = now.toISOString();
      await this.setAccountLockout(email, lockout, 900); // 15 minutes TTL
    } else {
      await this.setAccountLockout(email, lockout, 900); // 15 minutes TTL
    }
  }

  // Refresh Token Management
  static async setRefreshToken(userId, tokenId, expirationSeconds = 604800) {
    const key = `refresh:${userId}:${tokenId}`;
    const tokenData = {
      tokenId,
      userId,
      createdAt: new Date().toISOString(),
      isActive: true
    };
    await redis.setex(key, expirationSeconds, JSON.stringify(tokenData));
  }

  static async getRefreshToken(userId, tokenId) {
    const key = `refresh:${userId}:${tokenId}`;
    const data = await redis.get(key);
    return data ? JSON.parse(data) : null;
  }

  static async revokeRefreshToken(userId, tokenId) {
    const key = `refresh:${userId}:${tokenId}`;
    await redis.del(key);
  }

  static async revokeAllUserRefreshTokens(userId) {
    // Get all refresh tokens for user
    const pattern = `refresh:${userId}:*`;
    const keys = await redis.keys(pattern);
    
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  }

  // Security Event Logging (for quick access patterns)
  static async logSecurityEvent(eventType, details) {
    const key = `security:${eventType}:${Date.now()}`;
    const eventData = {
      type: eventType,
      timestamp: new Date().toISOString(),
      details
    };
    // Store for 7 days
    await redis.setex(key, 604800, JSON.stringify(eventData));
  }

  // Cleanup expired data (call this periodically)
  static async cleanupExpiredData() {
    const patterns = ['session:*', 'csrf:*', 'ratelimit:*', 'lockout:*', 'refresh:*'];
    
    for (const pattern of patterns) {
      const keys = await redis.keys(pattern);
      
      // Check TTL for each key and delete if expired
      for (const key of keys) {
        const ttl = await redis.ttl(key);
        if (ttl === -1) {
          // Key exists but has no TTL, set a default TTL
          await redis.expire(key, 86400); // 24 hours default
        }
      }
    }
  }

  // Health check
  static async healthCheck() {
    try {
      await redis.ping();
      return { status: 'healthy', timestamp: new Date().toISOString() };
    } catch (error) {
      return { status: 'unhealthy', error: error.message, timestamp: new Date().toISOString() };
    }
  }
}

export default redis;