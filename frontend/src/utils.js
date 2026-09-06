export function parseOverview(summary) {
  if (!summary) return null;

  try {
    const parsed = JSON.parse(summary);
    if (parsed && typeof parsed === 'object' && parsed.executive_summary) return parsed;
  } catch {
    // Older reports may contain a plain-text summary.
  }

  return {
    title: 'Basic Summary',
    executive_summary: summary,
    threat_actor: 'Unknown',
    malware_families: [],
    targeting: 'Not identified',
    attack_chain: [],
    key_findings: [],
    detection_opportunities: [],
    analyst_notes: ['Plain-text summary. Reprocess this report to generate the structured analyst overview.'],
    confidence: 'low',
  };
}

export function formatDate(value) {
  if (!value) return 'Unknown';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}
