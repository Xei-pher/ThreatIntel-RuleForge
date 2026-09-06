import { useMemo, useState } from 'react';
import { Archive, FileText, Search } from 'lucide-react';

import { EmptyState, Pill } from '../components/Common';
import { formatDate } from '../utils';

export function ReportsPage({ reports, selected, onSelectReport }) {
  const [query, setQuery] = useState('');
  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return reports;
    return reports.filter((report) => (
      `${report.filename} ${report.title} ${report.processing_status}`.toLowerCase().includes(normalized)
    ));
  }, [reports, query]);

  return (
    <div className="pageStack">
      <div className="pageHeader">
        <div>
          <div className="eyebrow"><Archive size={16} /> Report Library</div>
          <h2>Previous Reports</h2>
          <p>Open, reprocess, review, or export previously uploaded threat reports.</p>
        </div>
        <div className="searchBox">
          <Search size={17} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search reports..." />
        </div>
      </div>

      <div className="reportGrid">
        {!filtered.length ? (
          <EmptyState icon={<Search size={34} />} title="No matching reports" text="Try a different filename, title, or status." />
        ) : filtered.map((report) => (
          <button
            key={report.id}
            className={`reportCard ${selected?.id === report.id ? 'active' : ''}`}
            onClick={() => onSelectReport(report.id)}
          >
            <div className="reportCardIcon"><FileText size={24} /></div>
            <div className="reportCardBody">
              <h3>{report.title || report.filename}</h3>
              <p>{report.filename}</p>
              <small>{formatDate(report.upload_date)}</small>
            </div>
            <Pill tone={report.processing_status === 'processed' ? 'green' : report.processing_status === 'processing' ? 'orange' : 'gray'}>
              {report.processing_status}
            </Pill>
          </button>
        ))}
      </div>
    </div>
  );
}
