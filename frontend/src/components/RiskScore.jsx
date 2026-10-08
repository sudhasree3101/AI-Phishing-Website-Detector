import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

export default function RiskScore({ classification, riskLevel, confidence, score }) {
  const getIcon = () => {
    if (classification === 'LEGITIMATE') return <ShieldCheck size={22} />;
    if (classification === 'SUSPICIOUS') return <AlertTriangle size={22} />;
    return <ShieldAlert size={22} />;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        <div className={`status-badge status-${classification}`}>
          {getIcon()}
          <span>{classification} WEBSITE</span>
        </div>

        <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', background: 'rgba(255,255,255,0.05)', padding: '0.4rem 0.8rem', borderRadius: '0.5rem', border: '1px solid var(--border-color)' }}>
          Risk Level: <strong style={{ color: 'var(--text-primary)' }}>{riskLevel}</strong>
        </span>

        <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', background: 'rgba(255,255,255,0.05)', padding: '0.4rem 0.8rem', borderRadius: '0.5rem', border: '1px solid var(--border-color)' }}>
          Confidence: <strong style={{ color: 'var(--accent-cyan)' }}>{confidence}%</strong>
        </span>
      </div>
    </div>
  );
}
