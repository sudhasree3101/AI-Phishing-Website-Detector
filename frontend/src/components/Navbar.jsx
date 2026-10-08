import React from 'react';
import { Shield, ShieldAlert, Cpu } from 'lucide-react';

export default function Navbar() {
  return (
    <nav className="navbar">
      <div className="nav-brand">
        <Shield className="nav-brand-icon" size={28} />
        <span>AI Phishing Detector</span>
      </div>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
        <span className="nav-badge">
          <Cpu size={14} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
          Multi-Signal XAI
        </span>
      </div>
    </nav>
  );
}
