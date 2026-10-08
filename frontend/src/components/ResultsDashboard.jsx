import React from 'react';
import SecurityGauge from './SecurityGauge';
import RiskScore from './RiskScore';
import AnalysisCard from './AnalysisCard';
import FeatureList from './FeatureList';
import { 
  Globe, 
  Code, 
  FileText, 
  ShieldCheck, 
  Lock, 
  Tag, 
  Eye, 
  CheckCircle2, 
  AlertTriangle 
} from 'lucide-react';

export default function ResultsDashboard({ result }) {
  if (!result) return null;

  const {
    url,
    classification,
    risk_score,
    confidence,
    risk_level,
    summary,
    reasons = [],
    positive_indicators = [],
    warning_indicators = [],
    url_analysis,
    domain_analysis,
    html_analysis,
    nlp_analysis,
    visual_analysis,
    ssl_analysis,
    brand_analysis,
    feature_importance = [],
    is_demo_result
  } = result;

  return (
    <div>
      {/* Header Summary Card */}
      <div className={`results-header-card ${classification.toLowerCase()}`}>
        <SecurityGauge score={risk_score} riskLevel={risk_level} />

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Analyzed Target:
            </span>
            <span style={{ fontSize: '0.95rem', fontWeight: '600', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
              {url}
            </span>
            {is_demo_result && (
              <span className="card-risk-pill" style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', marginLeft: 'auto' }}>
                DEMO PRESET RESULT
              </span>
            )}
          </div>

          <RiskScore
            classification={classification}
            riskLevel={risk_level}
            confidence={confidence}
            score={risk_score}
          />

          <h3 className="summary-title" style={{ marginTop: '1.25rem' }}>
            Executive AI Assessment
          </h3>
          <p className="summary-text">{summary}</p>

          <div style={{ marginTop: '1rem' }}>
            <h4 style={{ fontSize: '0.95rem', marginBottom: '0.5rem', color: 'var(--text-primary)', fontWeight: '600' }}>
              Key Explainable AI Reasons:
            </h4>
            <div className="reasons-list">
              {reasons.map((reason, idx) => (
                <div key={idx} className="reason-bullet">
                  <span>{reason}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Grid of Analysis Perspective Cards */}
      <div className="analysis-grid">
        <AnalysisCard
          title="URL Analysis"
          icon={Globe}
          data={url_analysis}
          color="#38bdf8"
        />

        <AnalysisCard
          title="Domain & WHOIS Analysis"
          icon={Tag}
          data={domain_analysis}
          color="#a855f7"
        />

        <AnalysisCard
          title="HTML Structure Analysis"
          icon={Code}
          data={html_analysis}
          color="#3b82f6"
        />

        <AnalysisCard
          title="NLP & Text Analysis"
          icon={FileText}
          data={nlp_analysis}
          color="#ec4899"
        />

        <AnalysisCard
          title="Brand Impersonation"
          icon={ShieldCheck}
          data={brand_analysis}
          color="#f59e0b"
        />

        <AnalysisCard
          title="SSL / TLS Security"
          icon={Lock}
          data={ssl_analysis}
          color="#10b981"
        />

        <AnalysisCard
          title="Visual & Computer Vision"
          icon={Eye}
          data={visual_analysis}
          color="#06b6d4"
        />
      </div>

      {/* ML Feature Importance */}
      <FeatureList featureImportance={feature_importance} />
    </div>
  );
}
