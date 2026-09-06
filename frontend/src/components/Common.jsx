import { Brain, CheckCircle2, Clock3 } from 'lucide-react';

import { PROCESS_STEPS } from '../constants';

export function Pill({ children, tone = 'blue' }) {
  return <span className={`pill ${tone}`}>{children}</span>;
}

export function EmptyState({ icon, title, text }) {
  return (
    <div className="emptyState">
      <div className="emptyIcon">{icon}</div>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}

export function StatCard({ icon, label, value, hint }) {
  return (
    <div className="statCard">
      <div className="statIcon">{icon}</div>
      <div>
        <div className="statValue">{value}</div>
        <div className="statLabel">{label}</div>
        {hint && <div className="statHint">{hint}</div>}
      </div>
    </div>
  );
}

export function ProcessingOverlay({ progress, stepIndex }) {
  const currentStep = PROCESS_STEPS[stepIndex];

  return (
    <div className="processingOverlay">
      <div className="processingPanel">
        <div className="spinner"><Brain size={26} /></div>
        <h3>Processing threat report</h3>
        <p>{currentStep?.detail || 'Finalizing analysis'}</p>
        <div className="progressShell">
          <div className="progressBar" style={{ width: `${progress}%` }} />
        </div>
        <div className="progressMeta">
          <span>{currentStep?.label}</span>
          <b>{progress}%</b>
        </div>
        <div className="stepList">
          {PROCESS_STEPS.map((step, index) => (
            <div
              key={step.label}
              className={`stepItem ${index < stepIndex ? 'done' : ''} ${index === stepIndex ? 'active' : ''}`}
            >
              {index < stepIndex ? <CheckCircle2 size={16} /> : <Clock3 size={16} />}
              <span>{step.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function JudgeBadge({ item }) {
  if (!item?.judge_decision) return <span className="muted">Not judged</span>;

  const className = item.judge_decision === 'accepted'
    ? 'judgeAccepted'
    : item.judge_decision === 'review'
      ? 'judgeReview'
      : 'judgeRejected';

  return (
    <span className={`judgeBadge ${className}`} title={item.judge_reason || ''}>
      AI Judge: {item.judge_decision} · {item.judge_score ?? 'n/a'}
    </span>
  );
}
