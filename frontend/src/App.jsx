import React, { useState } from 'react';
import Navbar from './components/Navbar';
import UrlInput from './components/UrlInput';
import LoadingAnimation from './components/LoadingAnimation';
import ResultsDashboard from './components/ResultsDashboard';
import { AlertCircle } from 'lucide-react';
import './styles/app.css';

const FEATURE_ITEMS = [
  { icon: '🔗', title: 'URL Structure', desc: 'Length, entropy, hyphens, TLD risk, @ symbols, shorteners' },
  { icon: '🤖', title: 'Machine Learning', desc: 'Random Forest classifier trained on URL feature vectors' },
  { icon: '📄', title: 'HTML Inspection', desc: 'Forms, password fields, cross-domain submissions, JS' },
  { icon: '🧠', title: 'NLP Analysis', desc: 'Urgency language, credential requests, financial lures' },
  { icon: '🏷️', title: 'Brand Detection', desc: 'Checks 11 official brand domains for impersonation' },
  { icon: '🌐', title: 'Domain / WHOIS', desc: 'Registration age, registrar, and DNS nameservers' },
  { icon: '🔒', title: 'SSL / TLS', desc: 'Certificate issuer, validity period, and hostname match' },
];

export default function App() {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (url, isDemo = false) => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, is_demo: isDemo })
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Server error ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || 'An error occurred while connecting to the analysis backend.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app-container">
      <Navbar />

      <header className="hero">
        <h1 className="hero-title">AI Phishing Website Detector</h1>
        <p className="hero-subtitle">
          Analyze a website from multiple perspectives before you trust it — combining Machine Learning, URL structure, HTML parsing, NLP, Domain WHOIS, SSL inspection, and Brand Impersonation detection.
        </p>
      </header>

      <UrlInput onAnalyze={handleAnalyze} isLoading={isLoading} />

      {error && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          color: '#f87171',
          borderRadius: '0.75rem',
          padding: '1.25rem',
          marginBottom: '2rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem'
        }}>
          <AlertCircle size={24} />
          <div>
            <strong style={{ display: 'block', fontSize: '1rem' }}>Analysis Error</strong>
            <span style={{ fontSize: '0.9rem' }}>{error}</span>
          </div>
        </div>
      )}

      {isLoading && <LoadingAnimation />}

      {!isLoading && result && <ResultsDashboard result={result} />}

      {!isLoading && !result && !error && (
        <div style={{ marginTop: '0.5rem', marginBottom: '2rem' }}>
          <p style={{ textAlign: 'center', fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '1.25rem', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            7 Independent Analysis Signals Combined Into One Explainable Score
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '1rem' }}>
            {FEATURE_ITEMS.map((item, idx) => (
              <div key={idx} style={{
                background: 'rgba(17, 24, 39, 0.5)',
                border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: '0.75rem',
                padding: '1.25rem',
                textAlign: 'center',
                transition: 'border-color 0.2s ease',
              }}>
                <div style={{ fontSize: '1.75rem', marginBottom: '0.5rem' }}>{item.icon}</div>
                <div style={{ fontWeight: '700', fontSize: '0.9rem', marginBottom: '0.4rem', color: 'var(--text-primary)' }}>{item.title}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: '1.5' }}>{item.desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <footer className="footer">
        <p>AI-Powered Phishing Website Detector &copy; 2026 &mdash; Educational Cybersecurity &amp; Explainable AI Engine.</p>
      </footer>
    </div>
  );
}
