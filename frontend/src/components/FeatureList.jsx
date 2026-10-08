import React from 'react';
import { Cpu, BarChart2 } from 'lucide-react';

export default function FeatureList({ featureImportance }) {
  if (!featureImportance || featureImportance.length === 0) return null;

  return (
    <div className="card" style={{ marginTop: '1.5rem' }}>
      <div className="card-header">
        <div className="card-title">
          <BarChart2 size={20} color="var(--accent-purple)" />
          <span>Top Influential ML Features (Random Forest)</span>
        </div>
        <span className="card-risk-pill" style={{ background: 'rgba(129, 140, 248, 0.15)', color: 'var(--accent-purple)' }}>
          Explainable AI
        </span>
      </div>

      <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
        The supervised Machine Learning classifier weighted these features most heavily when calculating the risk score:
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
        {featureImportance.map((item, idx) => (
          <div
            key={idx}
            style={{
              background: 'rgba(15, 23, 42, 0.8)',
              border: '1px solid var(--border-color)',
              borderRadius: '0.5rem',
              padding: '0.85rem'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '0.4rem' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', color: 'var(--text-primary)' }}>
                {item.feature}
              </span>
              <span style={{ color: 'var(--accent-cyan)', fontWeight: '700' }}>
                {(item.importance * 100).toFixed(1)}%
              </span>
            </div>
            <div style={{ background: 'rgba(255,255,255,0.1)', height: '6px', borderRadius: '3px', overflow: 'hidden' }}>
              <div
                style={{
                  width: `${Math.min(100, item.importance * 300)}%`,
                  height: '100%',
                  background: 'linear-gradient(90deg, #38bdf8, #818cf8)',
                  borderRadius: '3px'
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
