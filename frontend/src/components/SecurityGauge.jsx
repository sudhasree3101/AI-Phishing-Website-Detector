import React from 'react';

export default function SecurityGauge({ score, riskLevel }) {
  let color = 'var(--status-low)';
  if (score >= 80) color = 'var(--status-critical)';
  else if (score >= 60) color = 'var(--status-high)';
  else if (score >= 30) color = 'var(--status-medium)';

  const backgroundGradient = `conic-gradient(${color} ${score * 3.6}deg, rgba(255, 255, 255, 0.08) 0deg)`;

  return (
    <div className="gauge-section">
      <div className="gauge-circle" style={{ background: backgroundGradient }}>
        <div
          style={{
            position: 'absolute',
            inset: '10px',
            background: 'var(--bg-dark)',
            borderRadius: '50%',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center'
          }}
        >
          <span className="gauge-score" style={{ color }}>
            {score}
          </span>
          <span className="gauge-label">RISK SCORE</span>
        </div>
      </div>
    </div>
  );
}
