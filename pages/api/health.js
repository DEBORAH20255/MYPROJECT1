import { SecurityManager } from '../../lib/security';
import { RedisManager } from '../../lib/redis';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ 
      success: false, 
      message: 'Method not allowed' 
    });
  }

  try {
    // Check Redis health
    const redisHealth = await SecurityManager.checkRedisHealth();
    
    // Check if we can perform basic Redis operations
    const testKey = `health-check:${Date.now()}`;
    await RedisManager.setSession(testKey, { test: true }, 10);
    const testData = await RedisManager.getSession(testKey);
    await RedisManager.deleteSession(testKey);

    const isRedisOperational = testData && testData.test === true;

    return res.status(200).json({
      success: true,
      timestamp: new Date().toISOString(),
      services: {
        redis: {
          status: redisHealth.status,
          operational: isRedisOperational,
          details: redisHealth
        },
        api: {
          status: 'healthy',
          operational: true
        }
      }
    });

  } catch (error) {
    return res.status(503).json({
      success: false,
      timestamp: new Date().toISOString(),
      error: 'Service health check failed',
      details: error.message
    });
  }
}