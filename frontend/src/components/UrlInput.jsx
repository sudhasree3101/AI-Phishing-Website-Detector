import React, { useState } from 'react';
import { Search, AlertTriangle, Play, Globe } from 'lucide-react';

export default function UrlInput({ onAnalyze, isLoading }) {
  const [inputUrl, setInputUrl] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (inputUrl.trim()) {
      onAnalyze(inputUrl.trim(), false);
    }
  };

  const handleDemoSelect = (demoUrl) => {
    setInputUrl(demoUrl);
    onAnalyze(demoUrl, true);
  };

  return (
    <div className="url-card">
      <form onSubmit={handleSubmit} className="url-form">
        <div className="input-wrapper">
          <Globe className="input-icon" size={20} />
          <input
            type="text"
            className="url-input"
            placeholder="https://paypal-login-security.xyz"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            disabled={isLoading}
          />
        </div>
        <button type="submit" className="btn-analyze" disabled={isLoading || !inputUrl.trim()}>
          <Search size={18} />
          {isLoading ? 'ANALYZING...' : 'ANALYZE WEBSITE'}
        </button>
      </form>

      <div className="notice-banner">
        <AlertTriangle size={18} />
        <span>Do not enter passwords or sensitive personal information into websites being analyzed.</span>
      </div>

      <div className="demo-bar">
        <span className="demo-label">Quick Demo Presets:</span>
        <button
          type="button"
          className="demo-btn"
          onClick={() => handleDemoSelect('https://paypal-login-security.xyz')}
          disabled={isLoading}
        >
          <Play size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
          Phishing Example (PayPal Spoof)
        </button>
        <button
          type="button"
          className="demo-btn"
          onClick={() => handleDemoSelect('https://free-bonus-update-2026.net')}
          disabled={isLoading}
        >
          <Play size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
          Suspicious Example
        </button>
        <button
          type="button"
          className="demo-btn"
          onClick={() => handleDemoSelect('https://google.com')}
          disabled={isLoading}
        >
          <Play size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
          Legitimate Example (Google)
        </button>
      </div>
    </div>
  );
}
