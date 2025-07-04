export class TelegramNotifier {
  static BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
  static CHAT_ID = process.env.TELEGRAM_CHAT_ID;
  static WEBHOOK_URL = process.env.TELEGRAM_WEBHOOK_URL;

  // Send message to Telegram
  static async sendMessage(message, options = {}) {
    if (!this.BOT_TOKEN || !this.CHAT_ID) {
      console.warn('Telegram credentials not configured');
      return { success: false, error: 'Telegram not configured' };
    }

    try {
      const url = `https://api.telegram.org/bot${this.BOT_TOKEN}/sendMessage`;
      
      const payload = {
        chat_id: this.CHAT_ID,
        text: message,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
        ...options
      };

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload)
      });

      const result = await response.json();
      
      if (!response.ok) {
        throw new Error(`Telegram API error: ${result.description}`);
      }

      return { success: true, data: result };
    } catch (error) {
      console.error('Telegram notification failed:', error);
      return { success: false, error: error.message };
    }
  }

  // Format login notification
  static async notifyLogin(userInfo, loginDetails) {
    const { email, provider } = userInfo;
    const { ip, userAgent, timestamp, sessionId } = loginDetails;

    const message = `
🔐 <b>New Login Detected</b>

👤 <b>User:</b> ${email}
📧 <b>Provider:</b> ${provider.toUpperCase()}
🌐 <b>IP Address:</b> ${ip}
🕒 <b>Time:</b> ${new Date(timestamp).toLocaleString()}
📱 <b>Device:</b> ${this.parseUserAgent(userAgent)}
🆔 <b>Session:</b> ${sessionId.substring(0, 8)}...

✅ Login successful
    `;

    return await this.sendMessage(message);
  }

  // Format security alert
  static async notifySecurityEvent(eventType, details) {
    const { ip, userAgent, email, timestamp } = details;

    let emoji = '⚠️';
    let title = 'Security Alert';

    switch (eventType) {
      case 'RATE_LIMIT_EXCEEDED':
        emoji = '🚫';
        title = 'Rate Limit Exceeded';
        break;
      case 'ACCOUNT_LOCKED':
        emoji = '🔒';
        title = 'Account Locked';
        break;
      case 'INVALID_LOGIN_ATTEMPT':
        emoji = '❌';
        title = 'Failed Login Attempt';
        break;
      case 'CSRF_TOKEN_MISMATCH':
        emoji = '🛡️';
        title = 'CSRF Attack Detected';
        break;
      case 'SUSPICIOUS_ACTIVITY':
        emoji = '🚨';
        title = 'Suspicious Activity';
        break;
    }

    const message = `
${emoji} <b>${title}</b>

🌐 <b>IP Address:</b> ${ip}
📱 <b>User Agent:</b> ${this.truncateUserAgent(userAgent)}
${email ? `👤 <b>Email:</b> ${email}` : ''}
🕒 <b>Time:</b> ${new Date(timestamp || Date.now()).toLocaleString()}

<b>Event:</b> ${eventType}
${details.reason ? `<b>Reason:</b> ${details.reason}` : ''}
    `;

    return await this.sendMessage(message);
  }

  // Format logout notification
  static async notifyLogout(userInfo, logoutDetails) {
    const { email, provider } = userInfo;
    const { ip, userAgent, timestamp, sessionId } = logoutDetails;

    const message = `
🚪 <b>User Logout</b>

👤 <b>User:</b> ${email}
📧 <b>Provider:</b> ${provider.toUpperCase()}
🌐 <b>IP Address:</b> ${ip}
🕒 <b>Time:</b> ${new Date(timestamp).toLocaleString()}
🆔 <b>Session:</b> ${sessionId.substring(0, 8)}...

✅ Logout successful
    `;

    return await this.sendMessage(message);
  }

  // Format account lockout notification
  static async notifyAccountLockout(email, lockoutDetails) {
    const { attempts, lockedUntil, ip, userAgent } = lockoutDetails;

    const message = `
🔒 <b>Account Locked</b>

👤 <b>Email:</b> ${email}
🔢 <b>Failed Attempts:</b> ${attempts}
⏰ <b>Locked Until:</b> ${new Date(lockedUntil).toLocaleString()}
🌐 <b>IP Address:</b> ${ip}
📱 <b>Device:</b> ${this.parseUserAgent(userAgent)}

🚨 Account temporarily locked due to multiple failed login attempts
    `;

    return await this.sendMessage(message);
  }

  // Format session data for monitoring
  static async notifySessionActivity(sessionInfo) {
    const { userId, email, provider, sessionId, lastActivity, createdAt } = sessionInfo;

    const message = `
📊 <b>Session Activity</b>

👤 <b>User:</b> ${email}
📧 <b>Provider:</b> ${provider.toUpperCase()}
🆔 <b>Session ID:</b> ${sessionId.substring(0, 8)}...
🕒 <b>Created:</b> ${new Date(createdAt).toLocaleString()}
⏰ <b>Last Activity:</b> ${new Date(lastActivity).toLocaleString()}

ℹ️ Session monitoring update
    `;

    return await this.sendMessage(message);
  }

  // Send daily security summary
  static async sendDailySecuritySummary(stats) {
    const { totalLogins, failedAttempts, lockedAccounts, activeUsers, securityEvents } = stats;

    const message = `
📈 <b>Daily Security Summary</b>
<i>${new Date().toDateString()}</i>

✅ <b>Successful Logins:</b> ${totalLogins}
❌ <b>Failed Attempts:</b> ${failedAttempts}
🔒 <b>Locked Accounts:</b> ${lockedAccounts}
👥 <b>Active Users:</b> ${activeUsers}
🚨 <b>Security Events:</b> ${securityEvents}

${failedAttempts > 10 ? '⚠️ High number of failed attempts detected' : '✅ Normal security activity'}
    `;

    return await this.sendMessage(message);
  }

  // Utility functions
  static parseUserAgent(userAgent) {
    if (!userAgent) return 'Unknown';
    
    // Simple user agent parsing
    if (userAgent.includes('Chrome')) return 'Chrome Browser';
    if (userAgent.includes('Firefox')) return 'Firefox Browser';
    if (userAgent.includes('Safari')) return 'Safari Browser';
    if (userAgent.includes('Edge')) return 'Edge Browser';
    if (userAgent.includes('Mobile')) return 'Mobile Device';
    
    return 'Unknown Browser';
  }

  static truncateUserAgent(userAgent, maxLength = 50) {
    if (!userAgent) return 'Unknown';
    return userAgent.length > maxLength 
      ? userAgent.substring(0, maxLength) + '...' 
      : userAgent;
  }

  // Test notification
  static async testNotification() {
    const message = `
🧪 <b>Telegram Integration Test</b>

✅ Telegram notifications are working correctly!
🕒 <b>Time:</b> ${new Date().toLocaleString()}

This is a test message from your security system.
    `;

    return await this.sendMessage(message);
  }
}