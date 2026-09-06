import {
  BarChart3,
  CheckCircle2,
  Crosshair,
  Database,
  Download,
  FileText,
  RefreshCcw,
  Shield,
  TerminalSquare,
} from 'lucide-react';

import { EmptyState, JudgeBadge, StatCard } from './Common';
import { Overview } from './Overview';

export function ReportWorkspace({
  selected,
  loading,
  activeTab,
  setActiveTab,
  processReport,
  exportReport,
  saveIoc,
  saveRule,
}) {
  if (!selected) {
    return (
      <EmptyState
        icon={<FileText size={34} />}
        title="No report selected"
        text="Choose a previous report or upload a new PDF."
      />
    );
  }

  const judgeAccepted = [
    ...(selected.iocs || []),
    ...(selected.mappings || []),
    ...(selected.detections || []),
  ].filter((item) => item.judge_decision === 'accepted').length;

  return (
    <>
      <header className="topbar">
        <div>
          <div className="eyebrow"><TerminalSquare size={16} /> Analyst Workspace</div>
          <h2>{selected.title || selected.filename}</h2>
          <p>{selected.filename} · Status: <b>{selected.processing_status}</b></p>
        </div>
        <div className="actions">
          <button className="secondaryBtn" onClick={processReport} disabled={loading}>
            <RefreshCcw size={16} /> {selected.processing_status === 'processed' ? 'Reprocess' : 'Process'}
          </button>
          <button className="primaryBtn" onClick={exportReport} disabled={selected.processing_status !== 'processed'}>
            <Download size={16} /> Export ZIP
          </button>
        </div>
      </header>

      <section className="workspaceStats">
        <StatCard icon={<Crosshair size={20} />} label="IOCs" value={selected.iocs?.length || 0} />
        <StatCard
          icon={<Database size={20} />}
          label="Enriched IOCs"
          value={selected.iocs?.filter((item) => item.enrichment_source).length || 0}
        />
        <StatCard icon={<CheckCircle2 size={20} />} label="Judge Accepted" value={judgeAccepted} />
        <StatCard icon={<BarChart3 size={20} />} label="MITRE Mappings" value={selected.mappings?.length || 0} />
        <StatCard icon={<Shield size={20} />} label="Sigma Rules" value={selected.detections?.length || 0} />
      </section>

      <nav className="tabs">
        {['overview', 'iocs', 'mitre', 'sigma', 'text'].map((tab) => (
          <button
            key={tab}
            className={activeTab === tab ? 'active' : ''}
            onClick={() => setActiveTab(tab)}
          >
            {tab.toUpperCase()}
          </button>
        ))}
      </nav>

      {activeTab === 'overview' && <Overview selected={selected} />}

      {activeTab === 'iocs' && (
        <section className="card">
          <div className="sectionHead">
            <h3>Extracted IOCs</h3>
            <span>
              {selected.iocs?.length || 0} indicators · {selected.iocs?.filter((item) => item.enrichment_source).length || 0} enriched · {selected.iocs?.filter((item) => item.judge_decision === 'review').length || 0} review
            </span>
          </div>
          <div className="tableWrap">
            <table>
              <thead>
                <tr>
                  <th>Approved</th>
                  <th>Judge</th>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Confidence</th>
                  <th>Enrichment</th>
                  <th>Context</th>
                </tr>
              </thead>
              <tbody>
                {selected.iocs?.map((ioc) => (
                  <tr key={ioc.id}>
                    <td>
                      <input
                        type="checkbox"
                        checked={ioc.is_approved}
                        onChange={(event) => saveIoc(ioc, { is_approved: event.target.checked })}
                      />
                    </td>
                    <td><JudgeBadge item={ioc} /></td>
                    <td>{ioc.ioc_type}</td>
                    <td><code>{ioc.value}</code></td>
                    <td>
                      <select value={ioc.confidence} onChange={(event) => saveIoc(ioc, { confidence: event.target.value })}>
                        <option>low</option>
                        <option>medium</option>
                        <option>high</option>
                      </select>
                    </td>
                    <td>
                      {ioc.enrichment_summary
                        ? <span className="enrichmentBadge">{ioc.enrichment_summary}</span>
                        : <span className="muted">Not enriched</span>}
                    </td>
                    <td>{ioc.source_context}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {activeTab === 'mitre' && (
        <section className="card">
          <div className="sectionHead">
            <h3>MITRE ATT&CK Mapping</h3>
            <span>{selected.mappings?.length || 0} techniques</span>
          </div>
          <div className="tableWrap">
            <table>
              <thead>
                <tr>
                  <th>Technique</th>
                  <th>Name</th>
                  <th>Confidence</th>
                  <th>Judge</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {selected.mappings?.map((mapping) => (
                  <tr key={mapping.id}>
                    <td><code>{mapping.technique_id}</code></td>
                    <td>{mapping.technique_name}</td>
                    <td>{mapping.confidence}</td>
                    <td><JudgeBadge item={mapping} /></td>
                    <td>{mapping.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {activeTab === 'sigma' && (
        <section className="card">
          <div className="sectionHead">
            <h3>Sigma Rules</h3>
            <span>
              {selected.detections?.length || 0} rules · {selected.detections?.filter((rule) => rule.judge_decision === 'review').length || 0} review
            </span>
          </div>
          {selected.detections?.map((rule) => (
            <div className="rule" key={rule.id}>
              <div className="ruleHead">
                <input value={rule.title} onChange={(event) => saveRule(rule, { title: event.target.value })} />
                <select value={rule.severity} onChange={(event) => saveRule(rule, { severity: event.target.value })}>
                  <option>low</option>
                  <option>medium</option>
                  <option>high</option>
                  <option>critical</option>
                </select>
                <JudgeBadge item={rule} />
              </div>
              <textarea value={rule.rule_content} onChange={(event) => saveRule(rule, { rule_content: event.target.value })} />
            </div>
          ))}
        </section>
      )}

      {activeTab === 'text' && (
        <section className="card">
          <div className="sectionHead"><h3>Extracted Text</h3><span>{selected.raw_text?.length || 0} chars</span></div>
          <pre>{selected.raw_text || 'No text extracted yet.'}</pre>
        </section>
      )}
    </>
  );
}
