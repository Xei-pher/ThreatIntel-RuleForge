import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Upload, FileText, Shield, Download, RefreshCcw } from 'lucide-react';
import { api } from './api/client';
import './styles.css';

function App() {
  const [reports, setReports] = useState([]);
  const [selected, setSelected] = useState(null);
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [error, setError] = useState('');

  const loadReports = async () => {
    const res = await api.get('/reports');
    setReports(res.data);
    if (!selected && res.data[0]) loadReport(res.data[0].id);
  };

  const loadReport = async (id) => {
    const res = await api.get(`/reports/${id}`);
    setSelected(res.data);
    setActiveTab('overview');
  };

  useEffect(() => { loadReports().catch(console.error); }, []);

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
    } catch (e) { setError(e.response?.data?.detail || e.message); }
    finally { setLoading(false); }
  };

  const processReport = async () => {
    if (!selected) return;
    setLoading(true); setError('');
    try {
      const res = await api.post(`/reports/${selected.id}/process`);
      setSelected(res.data);
    } catch (e) { setError(e.response?.data?.detail || e.message); }
    finally { setLoading(false); }
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

  return <div className="app">
    <aside className="sidebar">
      <div className="brand"><Shield size={28}/><div><h1>RuleForge</h1><p>Report → Detection</p></div></div>
      <div className="uploadBox">
        <input type="file" accept="application/pdf" onChange={e => setFile(e.target.files[0])} />
        <button onClick={uploadReport} disabled={!file || loading}><Upload size={16}/> Upload PDF</button>
      </div>
      <h3>Reports</h3>
      <div className="reportList">
        {reports.map(r => <button key={r.id} className={selected?.id === r.id ? 'selected' : ''} onClick={() => loadReport(r.id)}>
          <FileText size={16}/><span>{r.filename}</span><small>{r.processing_status}</small>
        </button>)}
      </div>
    </aside>

    <main className="main">
      {error && <div className="error">{error}</div>}
      {!selected ? <div className="empty">Upload a PDF threat report to start.</div> : <>
        <header className="topbar">
          <div><h2>{selected.title || selected.filename}</h2><p>Status: <b>{selected.processing_status}</b></p></div>
          <div className="actions">
            <button onClick={processReport} disabled={loading}><RefreshCcw size={16}/> Process</button>
            <button onClick={exportReport} disabled={selected.processing_status !== 'processed'}><Download size={16}/> Export ZIP</button>
          </div>
        </header>

        <nav className="tabs">
          {['overview','iocs','mitre','sigma','text'].map(t => <button key={t} className={activeTab === t ? 'active' : ''} onClick={() => setActiveTab(t)}>{t.toUpperCase()}</button>)}
        </nav>

        {activeTab === 'overview' && <section className="card"><h3>Summary</h3><p className="summary">{selected.summary || 'Process the report to generate a summary.'}</p><div className="stats"><span>{selected.iocs?.length || 0} IOCs</span><span>{selected.mappings?.length || 0} MITRE mappings</span><span>{selected.detections?.length || 0} Sigma rules</span></div></section>}

        {activeTab === 'iocs' && <section className="card"><h3>Extracted IOCs</h3><table><thead><tr><th>Approved</th><th>Type</th><th>Value</th><th>Confidence</th><th>Context</th></tr></thead><tbody>{selected.iocs?.map(ioc => <tr key={ioc.id}><td><input type="checkbox" checked={ioc.is_approved} onChange={e => saveIoc(ioc, {is_approved: e.target.checked})}/></td><td>{ioc.ioc_type}</td><td><code>{ioc.value}</code></td><td><select value={ioc.confidence} onChange={e => saveIoc(ioc,{confidence:e.target.value})}><option>low</option><option>medium</option><option>high</option></select></td><td>{ioc.source_context}</td></tr>)}</tbody></table></section>}

        {activeTab === 'mitre' && <section className="card"><h3>MITRE ATT&CK Mapping</h3><table><thead><tr><th>Technique</th><th>Name</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>{selected.mappings?.map(m => <tr key={m.id}><td><code>{m.technique_id}</code></td><td>{m.technique_name}</td><td>{m.confidence}</td><td>{m.evidence}</td></tr>)}</tbody></table></section>}

        {activeTab === 'sigma' && <section className="card"><h3>Sigma Rules</h3>{selected.detections?.map(rule => <div className="rule" key={rule.id}><div className="ruleHead"><input value={rule.title} onChange={e => saveRule(rule,{title:e.target.value})}/><select value={rule.severity} onChange={e => saveRule(rule,{severity:e.target.value})}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></div><textarea value={rule.rule_content} onChange={e => saveRule(rule,{rule_content:e.target.value})}/></div>)}</section>}

        {activeTab === 'text' && <section className="card"><h3>Extracted Text</h3><pre>{selected.raw_text || 'No text extracted yet.'}</pre></section>}
      </>}
    </main>
  </div>;
}

createRoot(document.getElementById('root')).render(<App />);
