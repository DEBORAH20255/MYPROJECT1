import { SecurityManager } from '../../../lib/security';
import { logSecurityEvent } from '../../../lib/logger';
import { RedisManager } from '../../../lib/redis';
import { TelegramNotifier } from '../../../lib/telegram';

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
    // Get tokens from cookies
    const cookies = SecurityManager.parseCookies(req.headers.cookie);
    const accessToken = cookies.accessToken;
    const refreshToken = cookies.refreshToken;

    let userInfo = null;

    if (accessToken) {
      try {
        const decoded = await SecurityManager.verifyAccessToken(accessToken);
        userInfo = {
          email: decoded.email,
          provider: decoded.provider,
          sessionId: decoded.sessionId
        };

        await SecurityManager.revokeSession(decoded.sessionId);
        
        // Also revoke refresh token if available
        if (refreshToken) {
          try {
            const refreshDecoded = await SecurityManager.verifyRefreshToken(refreshToken);
            await SecurityManager.revokeRefreshToken(refreshDecoded.userId, refreshDecoded.tokenId);
          } catch (error) {
            // Refresh token might be expired, but we still want to clear cookies
          }
        }
        
        await RedisManager.logSecurityEvent('USER_LOGOUT', {
          ip: clientIP,
          userAgent,
          sessionId: decoded.sessionId,
          email: decoded.email
        });

        // Send Telegram notification for logout
        await TelegramNotifier.notifyLogout(
          { email: decoded.email, provider: decoded.provider },
          {
            ip: clientIP,
            userAgent,
            timestamp: new Date().toISOString(),
            sessionId: decoded.sessionId
          }
        );
      } catch (error) {
        // Token might be expired, but we still want to clear cookies
      }
    }

    // Clear all auth cookies
    const clearCookies = [
      SecurityManager.createSecureCookie('accessToken', '', { maxAge: 0 }),
      SecurityManager.createSecureCookie('refreshToken', '', { maxAge: 0 }),
      SecurityManager.createSecureCookie('csrfToken', '', { maxAge: 0 })
    ];

    res.setHeader('Set-Cookie', clearCookies);

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    await RedisManager.logSecurityEvent('LOGOUT_ERROR', {
      ip: clientIP,
      userAgent,
      error: error.message
    });

    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
}