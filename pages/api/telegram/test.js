import { TelegramNotifier } from '../../../lib/telegram';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      success: false, 
      message: 'Method not allowed' 
    });
  }

  try {
    const result = await TelegramNotifier.testNotification();
    
    return res.status(200).json({
      success: result.success,
      message: result.success ? 'Test notification sent successfully' : 'Failed to send test notification',
      data: result.data,
      error: result.error
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
}