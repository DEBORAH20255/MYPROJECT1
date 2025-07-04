import { TelegramNotifier } from '../../../lib/telegram';
import { SecurityManager } from '../../../lib/security';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      success: false, 
      message: 'Method not allowed' 
    });
  }

  try {
    const update = req.body;
    
    // Basic webhook verification (you should implement proper verification)
    if (!update.message) {
      return res.status(200).json({ success: true });
    }

    const message = update.message;
    const chatId = message.chat.id;
    const text = message.text;

    // Handle commands
    if (text === '/status') {
      const redisHealth = await SecurityManager.checkRedisHealth();
      const statusMessage = `
🔧 <b>System Status</b>

🗄️ <b>Redis:</b> ${redisHealth.status}
⚡ <b>API:</b> Operational
🕒 <b>Last Check:</b> ${new Date().toLocaleString()}

${redisHealth.status === 'healthy' ? '✅ All systems operational' : '⚠️ Some issues detected'}
      `;
      
      await TelegramNotifier.sendMessage(statusMessage);
    }

    return res.status(200).json({ success: true });

  } catch (error) {
    console.error('Webhook error:', error);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
}