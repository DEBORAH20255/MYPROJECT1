import { SecurityManager } from '../../../lib/security';
import { refreshTokenSchema, validateInput } from '../../../lib/validation';
import { logSecurityEvent } from '../../../lib/logger';
import { RedisManager } from '../../../lib/redis';

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
      return res.status(503).json({
        success: false,
        message: 'Service temporarily unavailable'
      });
    }

    // Get refresh token from cookie or body
    const cookies = SecurityManager.parseCookies(req.headers.cookie);
    const refreshToken = cookies.refreshToken || req.body.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token required'
      });
    }

    // Validate refresh token
    const decoded = await SecurityManager.verifyRefreshToken(refreshToken);
    
    // Revoke old refresh token
    await SecurityManager.revokeRefreshToken(decoded.userId, decoded.tokenId);
    
    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken, sessionId, tokenId } = await SecurityManager.generateTokens(
      decoded.userId,
      decoded.email,
      decoded.provider
    );

    // Generate new CSRF token
    const csrfToken = await SecurityManager.generateCSRFToken(sessionId);

    // Set new secure cookies
    const accessTokenCookie = SecurityManager.createSecureCookie('accessToken', accessToken, {
      maxAge: 15 * 60 // 15 minutes
    });
    
    const refreshTokenCookie = SecurityManager.createSecureCookie('refreshToken', newRefreshToken, {
      maxAge: 7 * 24 * 60 * 60 // 7 days
    });

    const csrfCookie = SecurityManager.createSecureCookie('csrfToken', csrfToken, {
      maxAge: 60 * 60 // 1 hour
    });

    res.setHeader('Set-Cookie', [accessTokenCookie, refreshTokenCookie, csrfCookie]);

    return res.status(200).json({
      success: true,
      message: 'Tokens refreshed successfully',
      sessionId,
      csrfToken,
      expiresIn: '15m'
    });

  } catch (error) {
    await RedisManager.logSecurityEvent('TOKEN_REFRESH_ERROR', {
      ip: clientIP,
      userAgent,
      error: error.message
    });

    return res.status(401).json({
      success: false,
      message: 'Invalid or expired refresh token'
    });
  }
}