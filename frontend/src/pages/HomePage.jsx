import { Archive, CheckCircle2, Database, Eye, FileText, FileUp, Sparkles, Zap } from 'lucide-react';

import { EmptyState, Pill, StatCard } from '../components/Common';
import { formatDate } from '../utils';

const PIPELINE = [
  'PDF upload',
  'Text extraction',
  'Analyst overview',
  'IOC extraction',
  'Judge QA',
  'MITRE mapping',
  'Sigma generation',
  'CSV/YAML/Markdown export',
];

export function HomePage({ reports, onSelectReport, onUploadClick }) {
  const processed = reports.filter((report) => report.processing_status === 'processed').length;
  const lastReport = reports[0];

  return (
    <div className="pageStack">
      <section className="landingHero">
        <div>
          <div className="eyebrow"><Sparkles size={16} /> Threat Report to Detection Engineering</div>
          <h2>Turn PDF threat intelligence into reviewable Sigma detections.</h2>
          <p>Upload a report, extract IOCs, map ATT&CK techniques, generate rules, and export the package for analyst review.</p>
          <div className="heroActions">
            <button className="primaryBtn" onClick={onUploadClick}><FileUp size={17} /> Upload New Report</button>
            {lastReport && (
              <button className="secondaryBtn" onClick={() => onSelectReport(lastReport.id)}>
                <Eye size={17} /> Open Latest Report
              </button>
            )}
          </div>
        </div>
        <div className="heroPanel">
          <div className="miniTerminal">
            <div className="terminalDots"><span /><span /><span /></div>
            <p>$ ruleforge process report.pdf</p>
            <p className="ok">✓ IOC extraction complete</p>
            <p className="ok">✓ MITRE ATT&CK mapping complete</p>
            <p className="ok">✓ Sigma detections generated</p>
          </div>
        </div>
      </section>

      <section className="statsGrid">
        <StatCard icon={<Archive size={22} />} label="Total Reports" value={reports.length} hint="Uploaded PDFs" />
        <StatCard icon={<CheckCircle2 size={22} />} label="Processed" value={processed} hint="Ready for export" />
        <StatCard
          icon={<Database size={22} />}
          label="Latest Status"
          value={lastReport?.processing_status || 'None'}
          hint={lastReport?.filename || 'Upload a report to start'}
        />
        <StatCard icon={<Zap size={22} />} label="Pipeline" value="LLM + Rules" hint="Analyst-reviewed processing" />
      </section>

      <section className="contentGrid">
        <div className="card elevated">
          <div className="sectionHead"><h3>Recent Reports</h3><span>{reports.length} total</span></div>
          {!reports.length ? (
            <EmptyState icon={<FileText size={30} />} title="No reports yet" text="Upload your first PDF threat report to start the pipeline." />
          ) : (
            <div className="recentList">
              {reports.slice(0, 5).map((report) => (
                <button key={report.id} onClick={() => onSelectReport(report.id)}>
                  <div>
                    <b>{report.title || report.filename}</b>
                    <small>{report.filename} · {formatDate(report.upload_date)}</small>
                  </div>
                  <Pill tone={report.processing_status === 'processed' ? 'green' : 'orange'}>
                    {report.processing_status}
                  </Pill>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="card elevated">
          <div className="sectionHead"><h3>Processing Pipeline</h3><span>Current workflow</span></div>
          <div className="pipelineList">
            {PIPELINE.map((step) => <div key={step}><CheckCircle2 size={17} /><span>{step}</span></div>)}
          </div>
        </div>
      </section>
    </div>
  );
}
