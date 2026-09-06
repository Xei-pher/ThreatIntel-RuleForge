export const PROCESS_STEPS = [
  { label: 'Extracting PDF text', detail: 'Reading pages and normalizing report text' },
  { label: 'Building analyst overview', detail: 'Generating executive summary, attack chain, findings, and notes' },
  { label: 'Extracting IOCs', detail: 'Finding indicators, filtering noise, and enriching public IPs' },
  { label: 'Mapping MITRE ATT&CK', detail: 'Matching behaviors to likely techniques with evidence' },
  { label: 'Generating Sigma rules', detail: 'Creating reviewable detection logic from the report intelligence' },
  { label: 'Finalizing report package', detail: 'Saving results for review and export' },
];
