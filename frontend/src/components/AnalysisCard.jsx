import React from 'react';
import { AlertCircle, CheckCircle, Info } from 'lucide-react';

export default function AnalysisCard({ title, icon: Icon, data, color }) {
  if (!data) return null;

  const riskScore = data.risk_score || 0;
  const findings = data.findings || [];
  const metrics = data.metrics || {};

  let badgeColor = 'var(--status-low)';
  if (riskScore >= 70) badgeColor = 'var(--status-critical)';
  else if (riskScore >= 40) badgeColor = 'var(--status-medium)';

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          {Icon && <Icon size={20} color={color || 'var(--accent-cyan)'} />}
          <span>{title}</span>
        </div>
        <span
          className="card-risk-pill"
          style={{
            background: `${badgeColor}20`,
            color: badgeColor,
            border: `1px solid ${badgeColor}40`
          }}
        >
          {riskScore > 0 ? `Risk: ${riskScore}/100` : 'Clean'}
        </span>
      </div>

      <div style={{ marginBottom: '1rem' }}>
        {findings.map((finding, idx) => {
          const isWarning = finding.toLowerCase().includes('critical') || finding.toLowerCase().includes('suspicious') || finding.toLowerCase().includes('failed') || finding.toLowerCase().includes('impersonation') || finding.toLowerCase().includes('unusual');
          
          return (
            <div key={idx} className="card-finding">
              {isWarning ? (
                <AlertCircle size={15} color="var(--status-medium)" style={{ flexShrink: 0, marginTop: '2px' }} />
              ) : (
                <CheckCircle size={15} color="var(--status-low)" style={{ flexShrink: 0, marginTop: '2px' }} />
              )}
              <span>{finding}</span>
            </div>
          );
        })}
      </div>

      {Object.keys(metrics).length > 0 && (
        <div className="feature-tag-list">
          {Object.entries(metrics).slice(0, 6).map(([key, val], idx) => {
            if (val === null || val === undefined || Array.isArray(val) && val.length === 0) return null;
            return (
              <span key={idx} className="feature-tag">
                {key.replace(/_/g, ' ')}: <strong>{String(val)}</strong>
              </span>
            );
          })}
        </div>
      )}
    </div>
  );
}
