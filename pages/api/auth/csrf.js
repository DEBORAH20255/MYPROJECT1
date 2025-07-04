import { SecurityManager } from '../../../lib/security';

export default function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ 
      success: false, 
      message: 'Method not allowed' 
    });
  }

  try {
    // Generate a temporary session ID for CSRF token
    const tempSessionId = 'temp-' + Date.now();
    const csrfToken = SecurityManager.generateCSRFToken(tempSessionId);

    return res.status(200).json({
      success: true,
      csrfToken
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to generate CSRF token'
    });
  }
}