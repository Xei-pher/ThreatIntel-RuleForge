import { Activity, AlertTriangle, Brain, Crosshair, FileText } from 'lucide-react';

import { parseOverview } from '../utils';
import { EmptyState, Pill } from './Common';

function ListBlock({ title, items, icon }) {
  return (
    <div className="overviewBlock">
      <div className="blockTitle">{icon}{title}</div>
      {items?.length
        ? <ul>{items.map((item, index) => <li key={index}>{item}</li>)}</ul>
        : <p className="muted">Not identified in the report.</p>}
    </div>
  );
}

export function Overview({ selected }) {
  const overview = parseOverview(selected.summary);
  if (!overview) {
    return (
      <EmptyState
        icon={<Brain size={34} />}
        title="No analyst overview yet"
        text="Process the report to generate an analyst intelligence brief."
      />
    );
  }

  return (
    <section className="overviewGrid">
      <div className="heroCard">
        <div className="eyebrow"><Brain size={16} /> Analyst Brief</div>
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
        <div className="tagWrap">
          {overview.malware_families?.length
            ? overview.malware_families.map((name) => <Pill key={name} tone="purple">{name}</Pill>)
            : <span className="muted">None identified</span>}
        </div>
      </div>

      <ListBlock title="Attack Chain" items={overview.attack_chain} icon={<Activity size={17} />} />
      <ListBlock title="Key Findings" items={overview.key_findings} icon={<AlertTriangle size={17} />} />
      <ListBlock title="Detection Opportunities" items={overview.detection_opportunities} icon={<Crosshair size={17} />} />
      <ListBlock title="Analyst Notes" items={overview.analyst_notes} icon={<FileText size={17} />} />
    </section>
  );
}
