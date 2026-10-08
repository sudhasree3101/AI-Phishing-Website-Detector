import React, { useState, useEffect } from 'react';
import { CheckCircle2, Circle } from 'lucide-react';

const STEPS = [
  "Validating URL & SSRF rules",
  "Extracting URL structural features",
  "Checking WHOIS domain registration",
  "Fetching webpage HTML safely",
  "Analyzing HTML elements & form targets",
  "Scanning page text with NLP",
  "Detecting brand impersonation & spoofing",
  "Inspecting SSL certificate & encryption",
  "Performing visual analysis heuristics",
  "Calculating multi-signal risk score",
  "Generating Explainable AI summary"
];

export default function LoadingAnimation() {
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentStep((prev) => (prev < STEPS.length - 1 ? prev + 1 : prev));
    }, 250);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="loading-box">
      <div className="spinner-glow"></div>
      <h3 style={{ fontSize: '1.25rem', marginBottom: '0.5rem', fontWeight: '700' }}>
        Analyzing Website Security & Risk Profile...
      </h3>
      <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
        Synthesizing URL, HTML, NLP, SSL, and Domain intelligence signals.
      </p>

      <div className="loading-steps">
        {STEPS.map((step, idx) => {
          const isDone = idx < currentStep;
          const isActive = idx === currentStep;

          return (
            <div
              key={idx}
              className={`step-item ${isActive ? 'active' : ''} ${isDone ? 'done' : ''}`}
            >
              {isDone ? (
                <CheckCircle2 size={16} color="var(--status-low)" />
              ) : isActive ? (
                <div style={{ width: '16px', height: '16px', borderRadius: '50%', border: '2px solid var(--accent-cyan)', borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite' }} />
              ) : (
                <Circle size={16} color="var(--text-muted)" />
              )}
              <span>{step}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
