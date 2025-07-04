import { requireAuth } from '../../middleware/auth';

async function dashboardHandler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ 
      success: false, 
      message: 'Method not allowed' 
    });
  }

  // User info is available from the auth middleware
  const { user } = req;

  return res.status(200).json({
    success: true,
    message: 'Dashboard data retrieved successfully',
    user: {
      id: user.id,
      email: user.email,
      provider: user.provider
    },
    data: {
      lastLogin: new Date().toISOString(),
      documentsCount: 42,
      recentActivity: [
        { action: 'Document viewed', timestamp: new Date().toISOString() },
        { action: 'Profile updated', timestamp: new Date().toISOString() }
      ]
    }
  });
}

export default requireAuth(dashboardHandler);