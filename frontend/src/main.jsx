import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Upload,
  FileText,
  Shield,
  Download,
  RefreshCcw,
  AlertTriangle,
  Crosshair,
  Activity,
  Brain,
  Home,
  Archive,
  Search,
  CheckCircle2,
  Clock3,
  Database,
  Sparkles,
  FileUp,
  BarChart3,
  Zap,
  Eye,
  TerminalSquare
} from 'lucide-react';
import { api, describeApiError, API_BASE_URL } from './api/client';
import './styles.css';

const PROCESS_STEPS = [
  { label: 'Extracting PDF text', detail: 'Reading pages and normalizing report text' },
  { label: 'Building analyst overview', detail: 'Generating executive summary, attack chain, findings, and notes' },
  { label: 'Extracting IOCs', detail: 'Finding domains, URLs, IPs, hashes, paths, registry keys, filtering noise, and enriching public IPs' },
  { label: 'Mapping MITRE ATT&CK', detail: 'Matching behaviors to likely techniques with evidence' },
  { label: 'Generating Sigma rules', detail: 'Creating reviewable detection logic from the report intelligence' },
  { label: 'Finalizing report package', detail: 'Saving results for review and export' }
];

function parseOverview(summary) {
  if (!summary) return null;
  try {
    const parsed = JSON.parse(summary);
    if (parsed && typeof parsed === 'object' && parsed.executive_summary) return parsed;
  } catch (_) {}
  return {
    title: 'Basic Summary',
    executive_summary: summary,
    threat_actor: 'Unknown',
    malware_families: [],
    targeting: 'Not identified',
    attack_chain: [],
    key_findings: [],
    detection_opportunities: [],
    analyst_notes: ['Legacy/plain-text summary. Reprocess this report to generate the LLM overview.'],
    confidence: 'low'
  };
}

function fmtDate(value) {
  if (!value) return 'Unknown';
  try { return new Date(value).toLocaleString(); } catch (_) { return value; }
}

function Pill({ children, tone = 'blue' }) {
  return <span className={`pill ${tone}`}>{children}</span>;
}

function EmptyState({ icon, title, text }) {
  return <div className="emptyState">
    <div className="emptyIcon">{icon}</div>
    <h3>{title}</h3>
    <p>{text}</p>
  </div>;
}

function StatCard({ icon, label, value, hint }) {
  return <div className="statCard">
    <div className="statIcon">{icon}</div>
    <div>
      <div className="statValue">{value}</div>
      <div className="statLabel">{label}</div>
      {hint && <div className="statHint">{hint}</div>}
    </div>
  </div>;
}

function ListBlock({ title, items, icon }) {
  return <div className="overviewBlock">
    <div className="blockTitle">{icon}{title}</div>
    {items?.length ? <ul>{items.map((item, idx) => <li key={idx}>{item}</li>)}</ul> : <p className="muted">Not identified in the report.</p>}
  </div>;
}

function ProcessingOverlay({ progress, stepIndex }) {
  return <div className="processingOverlay">
    <div className="processingPanel">
      <div className="spinner"><Brain size={26}/></div>
      <h3>Processing threat report</h3>
      <p>{PROCESS_STEPS[stepIndex]?.detail || 'Finalizing analysis'}</p>
      <div className="progressShell"><div className="progressBar" style={{ width: `${progress}%` }} /></div>
      <div className="progressMeta"><span>{PROCESS_STEPS[stepIndex]?.label}</span><b>{progress}%</b></div>
      <div className="stepList">
        {PROCESS_STEPS.map((step, idx) => <div key={step.label} className={`stepItem ${idx < stepIndex ? 'done' : ''} ${idx === stepIndex ? 'active' : ''}`}>
          {idx < stepIndex ? <CheckCircle2 size={16}/> : <Clock3 size={16}/>}<span>{step.label}</span>
        </div>)}
      </div>
    </div>
  </div>;
}

function Overview({ selected }) {
  const overview = parseOverview(selected.summary);
  if (!overview) {
    return <EmptyState icon={<Brain size={34}/>} title="No analyst overview yet" text="Process the report to generate an LLM-powered intelligence brief." />;
  }

  return <section className="overviewGrid">
    <div className="heroCard">
      <div className="eyebrow"><Brain size={16}/> LLM Analyst Brief</div>
      <h3>{overview.title || selected.title || selected.filename}</h3>
      <p>{overview.executive_summary}</p>
      <div className="overviewMeta">
        <Pill>Confidence: {overview.confidence || 'medium'}</Pill>
        <Pill tone="dark">Actor: {overview.threat_actor || 'Unknown'}</Pill>
        <Pill>{selected.iocs?.length || 0} IOCs</Pill>
        <Pill>{selected.mappings?.length || 0} MITRE</Pill>
        <Pill>{selected.detections?.length || 0} Sigma</Pill>
      </div>
    </div>

    <div className="sideCard">
      <h4>Targeting</h4>
      <p>{overview.targeting || 'Not identified.'}</p>
      <h4>Malware / Tools</h4>
      <div className="tagWrap">{overview.malware_families?.length ? overview.malware_families.map(x => <Pill key={x} tone="purple">{x}</Pill>) : <span className="muted">None identified</span>}</div>
    </div>

    <ListBlock title="Attack Chain" items={overview.attack_chain} icon={<Activity size={17}/>} />
    <ListBlock title="Key Findings" items={overview.key_findings} icon={<AlertTriangle size={17}/>} />
    <ListBlock title="Detection Opportunities" items={overview.detection_opportunities} icon={<Crosshair size={17}/>} />
    <ListBlock title="Analyst Notes" items={overview.analyst_notes} icon={<FileText size={17}/>} />
  </section>;
}

function HomePage({ reports, selected, onSelectReport, onUploadClick }) {
  const processed = reports.filter(r => r.processing_status === 'processed').length;
  const lastReport = reports[0];

  return <div className="pageStack">
    <section className="landingHero">
      <div>
        <div className="eyebrow"><Sparkles size={16}/> Threat Report to Detection Engineering</div>
        <h2>Turn PDF threat intelligence into reviewable Sigma detections.</h2>
        <p>Upload a report, extract IOCs, map ATT&CK techniques, generate rules, and export the package for analyst review.</p>
        <div className="heroActions">
          <button className="primaryBtn" onClick={onUploadClick}><FileUp size={17}/> Upload New Report</button>
          {lastReport && <button className="secondaryBtn" onClick={() => onSelectReport(lastReport.id)}><Eye size={17}/> Open Latest Report</button>}
        </div>
      </div>
      <div className="heroPanel">
        <div className="miniTerminal">
          <div className="terminalDots"><span></span><span></span><span></span></div>
          <p>$ ruleforge process report.pdf</p>
          <p className="ok">✓ IOC extraction complete</p>
          <p className="ok">✓ MITRE ATT&CK mapping complete</p>
          <p className="ok">✓ Sigma detections generated</p>
        </div>
      </div>
    </section>

    <section className="statsGrid">
      <StatCard icon={<Archive size={22}/>} label="Total Reports" value={reports.length} hint="Uploaded PDFs" />
      <StatCard icon={<CheckCircle2 size={22}/>} label="Processed" value={processed} hint="Ready for export" />
      <StatCard icon={<Database size={22}/>} label="Latest Status" value={lastReport?.processing_status || 'None'} hint={lastReport?.filename || 'Upload a report to start'} />
      <StatCard icon={<Zap size={22}/>} label="Pipeline" value="LLM + Fallback" hint="Resilient processing" />
    </section>

    <section className="contentGrid">
      <div className="card elevated">
        <div className="sectionHead"><h3>Recent Reports</h3><span>{reports.length} total</span></div>
        {!reports.length ? <EmptyState icon={<FileText size={30}/>} title="No reports yet" text="Upload your first PDF threat report to start the pipeline." /> :
          <div className="recentList">{reports.slice(0, 5).map(r => <button key={r.id} onClick={() => onSelectReport(r.id)}>
            <div><b>{r.title || r.filename}</b><small>{r.filename} · {fmtDate(r.upload_date)}</small></div>
            <Pill tone={r.processing_status === 'processed' ? 'green' : 'orange'}>{r.processing_status}</Pill>
          </button>)}</div>}
      </div>
      <div className="card elevated">
        <div className="sectionHead"><h3>MVP Pipeline</h3><span>Current build</span></div>
        <div className="pipelineList">
          {['PDF upload', 'Text extraction', 'LLM overview', 'IOC extraction', 'MITRE mapping', 'Sigma generation', 'CSV/YAML/Markdown export'].map(x => <div key={x}><CheckCircle2 size={17}/><span>{x}</span></div>)}
        </div>
      </div>
    </section>
  </div>;
}

function ReportsPage({ reports, selected, onSelectReport }) {
  const [query, setQuery] = useState('');
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return reports;
    return reports.filter(r => `${r.filename} ${r.title} ${r.processing_status}`.toLowerCase().includes(q));
  }, [reports, query]);

  return <div className="pageStack">
    <div className="pageHeader">
      <div>
        <div className="eyebrow"><Archive size={16}/> Report Library</div>
        <h2>Previous Reports</h2>
        <p>Open, reprocess, review, or export previously uploaded threat reports.</p>
      </div>
      <div className="searchBox"><Search size={17}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search reports..." /></div>
    </div>
    <div className="reportGrid">
      {!filtered.length ? <EmptyState icon={<Search size={34}/>} title="No matching reports" text="Try a different filename, title, or status." /> : filtered.map(r => <button key={r.id} className={`reportCard ${selected?.id === r.id ? 'active' : ''}`} onClick={() => onSelectReport(r.id)}>
        <div className="reportCardIcon"><FileText size={24}/></div>
        <div className="reportCardBody">
          <h3>{r.title || r.filename}</h3>
          <p>{r.filename}</p>
          <small>{fmtDate(r.upload_date)}</small>
        </div>
        <Pill tone={r.processing_status === 'processed' ? 'green' : r.processing_status === 'processing' ? 'orange' : 'gray'}>{r.processing_status}</Pill>
      </button>)}
    </div>
  </div>;
}

function ReportWorkspace({ selected, loading, activeTab, setActiveTab, processReport, exportReport, saveIoc, saveRule }) {
  if (!selected) return <EmptyState icon={<FileText size={34}/>} title="No report selected" text="Choose a previous report or upload a new PDF." />;

  return <>
    <header className="topbar">
      <div>
        <div className="eyebrow"><TerminalSquare size={16}/> Analyst Workspace</div>
        <h2>{selected.title || selected.filename}</h2>
        <p>{selected.filename} · Status: <b>{selected.processing_status}</b></p>
      </div>
      <div className="actions">
        <button className="secondaryBtn" onClick={processReport} disabled={loading}><RefreshCcw size={16}/> {selected.processing_status === 'processed' ? 'Reprocess' : 'Process'}</button>
        <button className="primaryBtn" onClick={exportReport} disabled={selected.processing_status !== 'processed'}><Download size={16}/> Export ZIP</button>
      </div>
    </header>

    <section className="workspaceStats">
      <StatCard icon={<Crosshair size={20}/>} label="IOCs" value={selected.iocs?.length || 0} />
      <StatCard icon={<Database size={20}/>} label="Enriched IOCs" value={selected.iocs?.filter(i => i.enrichment_source).length || 0} />
      <StatCard icon={<BarChart3 size={20}/>} label="MITRE Mappings" value={selected.mappings?.length || 0} />
      <StatCard icon={<Shield size={20}/>} label="Sigma Rules" value={selected.detections?.length || 0} />
    </section>

    <nav className="tabs">
      {['overview','iocs','mitre','sigma','text'].map(t => <button key={t} className={activeTab === t ? 'active' : ''} onClick={() => setActiveTab(t)}>{t.toUpperCase()}</button>)}
    </nav>

    {activeTab === 'overview' && <Overview selected={selected} />}

    {activeTab === 'iocs' && <section className="card"><div className="sectionHead"><h3>Extracted IOCs</h3><span>{selected.iocs?.length || 0} indicators · {selected.iocs?.filter(i => i.enrichment_source).length || 0} enriched</span></div><div className="tableWrap"><table><thead><tr><th>Approved</th><th>Type</th><th>Value</th><th>Confidence</th><th>Enrichment</th><th>Context</th></tr></thead><tbody>{selected.iocs?.map(ioc => <tr key={ioc.id}><td><input type="checkbox" checked={ioc.is_approved} onChange={e => saveIoc(ioc, {is_approved: e.target.checked})}/></td><td>{ioc.ioc_type}</td><td><code>{ioc.value}</code></td><td><select value={ioc.confidence} onChange={e => saveIoc(ioc,{confidence:e.target.value})}><option>low</option><option>medium</option><option>high</option></select></td><td>{ioc.enrichment_summary ? <span className="enrichmentBadge">{ioc.enrichment_summary}</span> : <span className="muted">Not enriched</span>}</td><td>{ioc.source_context}</td></tr>)}</tbody></table></div></section>}

    {activeTab === 'mitre' && <section className="card"><div className="sectionHead"><h3>MITRE ATT&CK Mapping</h3><span>{selected.mappings?.length || 0} techniques</span></div><div className="tableWrap"><table><thead><tr><th>Technique</th><th>Name</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>{selected.mappings?.map(m => <tr key={m.id}><td><code>{m.technique_id}</code></td><td>{m.technique_name}</td><td>{m.confidence}</td><td>{m.evidence}</td></tr>)}</tbody></table></div></section>}

    {activeTab === 'sigma' && <section className="card"><div className="sectionHead"><h3>Sigma Rules</h3><span>{selected.detections?.length || 0} rules</span></div>{selected.detections?.map(rule => <div className="rule" key={rule.id}><div className="ruleHead"><input value={rule.title} onChange={e => saveRule(rule,{title:e.target.value})}/><select value={rule.severity} onChange={e => saveRule(rule,{severity:e.target.value})}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></div><textarea value={rule.rule_content} onChange={e => saveRule(rule,{rule_content:e.target.value})}/></div>)}</section>}

    {activeTab === 'text' && <section className="card"><div className="sectionHead"><h3>Extracted Text</h3><span>{selected.raw_text?.length || 0} chars</span></div><pre>{selected.raw_text || 'No text extracted yet.'}</pre></section>}
  </>;
}

function App() {
  const [reports, setReports] = useState([]);
  const [selected, setSelected] = useState(null);
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activePage, setActivePage] = useState('home');
  const [activeTab, setActiveTab] = useState('overview');
  const [error, setError] = useState('');
  const [apiHealth, setApiHealth] = useState(null);
  const [progress, setProgress] = useState(0);

  const loadReports = async () => {
    const res = await api.get('/reports');
    setReports(res.data);
    if (!selected && res.data[0]) setSelected(res.data[0]);
  };

  const loadReport = async (id, page = 'workspace') => {
    const res = await api.get(`/reports/${id}`);
    setSelected(res.data);
    setActiveTab('overview');
    setActivePage(page);
  };

  useEffect(() => {
    api.get('/health')
      .then(res => setApiHealth(res.data))
      .catch(e => setError(describeApiError(e)));
    loadReports().catch(e => setError(describeApiError(e)));
  }, []);

  useEffect(() => {
    if (!loading) return;
    setProgress(8);
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 94) return prev;
        const increment = prev < 35 ? 5 : prev < 70 ? 3 : 1;
        return Math.min(94, prev + increment);
      });
    }, 900);
    return () => clearInterval(interval);
  }, [loading]);

  const stepIndex = Math.min(PROCESS_STEPS.length - 1, Math.floor((progress / 100) * PROCESS_STEPS.length));

  const uploadReport = async () => {
    if (!file) return;
    setLoading(true); setError('');
    try {
      const form = new FormData();
      form.append('file', file);
      const res = await api.post('/reports/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } });
      await loadReports();
      await loadReport(res.data.id);
      setFile(null);
      setActivePage('workspace');
    } catch (e) { setError(describeApiError(e)); }
    finally { setProgress(100); setTimeout(() => setLoading(false), 250); }
  };

  const processReport = async () => {
    if (!selected) return;
    setLoading(true); setError(''); setProgress(4);
    try {
      const res = await api.post(`/reports/${selected.id}/process`);
      setProgress(100);
      setSelected(res.data);
      await loadReports();
    } catch (e) { setError(describeApiError(e)); }
    finally { setTimeout(() => setLoading(false), 350); }
  };

  const exportReport = async () => {
    if (!selected) return;
    const res = await api.post(`/reports/${selected.id}/export`, {}, { responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([res.data]));
    const a = document.createElement('a');
    a.href = url;
    a.download = `report_${selected.id}_export.zip`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const saveIoc = async (ioc, patch) => {
    const res = await api.patch(`/iocs/${ioc.id}`, patch);
    setSelected(prev => ({ ...prev, iocs: prev.iocs.map(x => x.id === ioc.id ? res.data : x) }));
  };

  const saveRule = async (rule, patch) => {
    const res = await api.patch(`/detections/${rule.id}`, patch);
    setSelected(prev => ({ ...prev, detections: prev.detections.map(x => x.id === rule.id ? res.data : x) }));
  };

  const openFilePicker = () => document.getElementById('pdf-upload')?.click();

  return <div className="appShell">
    {loading && <ProcessingOverlay progress={progress} stepIndex={stepIndex} />}
    <aside className="sidebar">
      <div className="brand"><Shield size={30}/><div><h1>RuleForge</h1><p>Report → Detection</p></div></div>
      <nav className="sideNav">
        <button className={activePage === 'home' ? 'active' : ''} onClick={() => setActivePage('home')}><Home size={17}/> Home</button>
        <button className={activePage === 'reports' ? 'active' : ''} onClick={() => setActivePage('reports')}><Archive size={17}/> Previous Reports</button>
        <button className={activePage === 'workspace' ? 'active' : ''} onClick={() => setActivePage('workspace')}><TerminalSquare size={17}/> Workspace</button>
      </nav>
      <div className="uploadBox">
        <label>Upload Threat Report</label>
        <input id="pdf-upload" type="file" accept="application/pdf" onChange={e => setFile(e.target.files[0])} />
        <button onClick={uploadReport} disabled={!file || loading}><Upload size={16}/> {file ? `Upload ${file.name.slice(0, 18)}...` : 'Upload PDF'}</button>
      </div>
      <div className="sidebarFooter">
        <p><b>{reports.length}</b> reports stored</p>
        <p><b>{reports.filter(r => r.processing_status === 'processed').length}</b> processed</p>
        <p className="apiBase">API: {API_BASE_URL}</p>
        {apiHealth && <p className="apiOk">Backend: {apiHealth.status}</p>}
      </div>
    </aside>

    <main className="main">
      {error && <div className="error">{error}</div>}
      {activePage === 'home' && <HomePage reports={reports} selected={selected} onSelectReport={loadReport} onUploadClick={openFilePicker} />}
      {activePage === 'reports' && <ReportsPage reports={reports} selected={selected} onSelectReport={loadReport} />}
      {activePage === 'workspace' && <ReportWorkspace selected={selected} loading={loading} activeTab={activeTab} setActiveTab={setActiveTab} processReport={processReport} exportReport={exportReport} saveIoc={saveIoc} saveRule={saveRule} />}
    </main>
  </div>;
}

createRoot(document.getElementById('root')).render(<App />);