import { SecurityManager } from '../lib/security';
import { logSecurityEvent } from '../lib/logger';
import { RedisManager } from '../lib/redis';

export function requireAuth(handler) {
  return async (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    try {
      // Check Redis health
      const redisHealth = await SecurityManager.checkRedisHealth();
      if (redisHealth.status !== 'healthy') {
        return res.status(503).json({
          success: false,
          message: 'Service temporarily unavailable'
        });
      }

      // Get access token from cookie
      const cookies = SecurityManager.parseCookies(req.headers.cookie);
      const accessToken = cookies.accessToken;

      if (!accessToken) {
        return res.status(401).json({
          success: false,
          message: 'Access token required'
        });
      }

      // Verify access token
      const decoded = await SecurityManager.verifyAccessToken(accessToken);
      
      // Add user info to request
      req.user = {
        id: decoded.userId,
        email: decoded.email,
        provider: decoded.provider,
        sessionId: decoded.sessionId
      };

      return handler(req, res);

    } catch (error) {
      await RedisManager.logSecurityEvent('AUTH_MIDDLEWARE_ERROR', {
        ip: clientIP,
        userAgent,
        error: error.message
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid or expired access token'
      });
    }
  };
}

export function requireCSRF(handler) {
  return async (req, res) => {
    if (req.method === 'GET') {
      return handler(req, res);
    }

    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    try {
      const cookies = SecurityManager.parseCookies(req.headers.cookie);
      const csrfTokenFromCookie = cookies.csrfToken;
      const csrfTokenFromHeader = req.headers['x-csrf-token'] || req.body.csrfToken;

      if (!csrfTokenFromCookie || !csrfTokenFromHeader) {
        await RedisManager.logSecurityEvent('CSRF_TOKEN_MISSING', {
          ip: clientIP,
          userAgent
        });

        return res.status(403).json({
          success: false,
          message: 'CSRF token required'
        });
      }

      if (csrfTokenFromCookie !== csrfTokenFromHeader) {
        await RedisManager.logSecurityEvent('CSRF_TOKEN_MISMATCH', {
          ip: clientIP,
          userAgent
        });

        return res.status(403).json({
          success: false,
          message: 'Invalid CSRF token'
        });
      }

      return handler(req, res);

    } catch (error) {
      await RedisManager.logSecurityEvent('CSRF_MIDDLEWARE_ERROR', {
        ip: clientIP,
        userAgent,
        error: error.message
      });

      return res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  };
}