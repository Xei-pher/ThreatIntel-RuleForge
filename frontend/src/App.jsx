import { useEffect, useState } from 'react';
import { Archive, Home, Shield, TerminalSquare, Upload } from 'lucide-react';

import { api, API_BASE_URL, describeApiError } from './api/client';
import { ProcessingOverlay } from './components/Common';
import { ReportWorkspace } from './components/ReportWorkspace';
import { PROCESS_STEPS } from './constants';
import { HomePage } from './pages/HomePage';
import { ReportsPage } from './pages/ReportsPage';

export default function App() {
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
    const response = await api.get('/reports');
    setReports(response.data);
    setSelected((current) => current || response.data[0] || null);
  };

  const loadReport = async (id, page = 'workspace') => {
    const response = await api.get(`/reports/${id}`);
    setSelected(response.data);
    setActiveTab('overview');
    setActivePage(page);
  };

  useEffect(() => {
    api.get('/health')
      .then((response) => setApiHealth(response.data))
      .catch((requestError) => setError(describeApiError(requestError)));
    loadReports().catch((requestError) => setError(describeApiError(requestError)));
  }, []);

  useEffect(() => {
    if (!loading) return undefined;

    setProgress(8);
    const interval = setInterval(() => {
      setProgress((current) => {
        if (current >= 94) return current;
        const increment = current < 35 ? 5 : current < 70 ? 3 : 1;
        return Math.min(94, current + increment);
      });
    }, 900);

    return () => clearInterval(interval);
  }, [loading]);

  const stepIndex = Math.min(
    PROCESS_STEPS.length - 1,
    Math.floor((progress / 100) * PROCESS_STEPS.length),
  );

  const uploadReport = async () => {
    if (!file) return;

    setLoading(true);
    setError('');
    try {
      const form = new FormData();
      form.append('file', file);
      const response = await api.post('/reports/upload', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      await loadReports();
      await loadReport(response.data.id);
      setFile(null);
      setActivePage('workspace');
    } catch (requestError) {
      setError(describeApiError(requestError));
    } finally {
      setProgress(100);
      setTimeout(() => setLoading(false), 250);
    }
  };

  const processReport = async () => {
    if (!selected) return;

    setLoading(true);
    setError('');
    setProgress(4);
    try {
      const response = await api.post(`/reports/${selected.id}/process`);
      setProgress(100);
      setSelected(response.data);
      await loadReports();
    } catch (requestError) {
      setError(describeApiError(requestError));
    } finally {
      setTimeout(() => setLoading(false), 350);
    }
  };

  const exportReport = async () => {
    if (!selected) return;

    setError('');
    try {
      const response = await api.post(`/reports/${selected.id}/export`, {}, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.download = `report_${selected.id}_export.zip`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (requestError) {
      setError(describeApiError(requestError));
    }
  };

  const saveIoc = async (ioc, patch) => {
    try {
      const response = await api.patch(`/iocs/${ioc.id}`, patch);
      setSelected((current) => ({
        ...current,
        iocs: current.iocs.map((item) => item.id === ioc.id ? response.data : item),
      }));
    } catch (requestError) {
      setError(describeApiError(requestError));
    }
  };

  const saveRule = async (rule, patch) => {
    try {
      const response = await api.patch(`/detections/${rule.id}`, patch);
      setSelected((current) => ({
        ...current,
        detections: current.detections.map((item) => item.id === rule.id ? response.data : item),
      }));
    } catch (requestError) {
      setError(describeApiError(requestError));
    }
  };

  const openFilePicker = () => document.getElementById('pdf-upload')?.click();

  return (
    <div className="appShell">
      {loading && <ProcessingOverlay progress={progress} stepIndex={stepIndex} />}

      <aside className="sidebar">
        <div className="brand">
          <Shield size={30} />
          <div><h1>RuleForge</h1><p>Report → Detection</p></div>
        </div>

        <nav className="sideNav">
          <button className={activePage === 'home' ? 'active' : ''} onClick={() => setActivePage('home')}>
            <Home size={17} /> Home
          </button>
          <button className={activePage === 'reports' ? 'active' : ''} onClick={() => setActivePage('reports')}>
            <Archive size={17} /> Previous Reports
          </button>
          <button className={activePage === 'workspace' ? 'active' : ''} onClick={() => setActivePage('workspace')}>
            <TerminalSquare size={17} /> Workspace
          </button>
        </nav>

        <div className="uploadBox">
          <label>Upload Threat Report</label>
          <input id="pdf-upload" type="file" accept="application/pdf" onChange={(event) => setFile(event.target.files[0])} />
          <button onClick={uploadReport} disabled={!file || loading}>
            <Upload size={16} /> {file ? `Upload ${file.name.slice(0, 18)}...` : 'Upload PDF'}
          </button>
        </div>

        <div className="sidebarFooter">
          <p><b>{reports.length}</b> reports stored</p>
          <p><b>{reports.filter((report) => report.processing_status === 'processed').length}</b> processed</p>
          <p className="apiBase">API: {API_BASE_URL}</p>
          {apiHealth && <p className="apiOk">Backend: {apiHealth.status}</p>}
        </div>
      </aside>

      <main className="main">
        {error && <div className="error">{error}</div>}
        {activePage === 'home' && (
          <HomePage reports={reports} onSelectReport={loadReport} onUploadClick={openFilePicker} />
        )}
        {activePage === 'reports' && (
          <ReportsPage reports={reports} selected={selected} onSelectReport={loadReport} />
        )}
        {activePage === 'workspace' && (
          <ReportWorkspace
            selected={selected}
            loading={loading}
            activeTab={activeTab}
            setActiveTab={setActiveTab}
            processReport={processReport}
            exportReport={exportReport}
            saveIoc={saveIoc}
            saveRule={saveRule}
          />
        )}
      </main>
    </div>
  );
}
