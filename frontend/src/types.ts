export type Severity = "critical" | "high" | "medium" | "low";
export interface Summary {
  total: number;
  active: number;
  suppressed: number;
  severities: Record<Severity, number>;
  files_scanned: number;
  lines_scanned: number;
  duration_seconds: number;
  warnings: string[];
  engines: Record<
    string,
    { status: string; detail?: string; advisory_matches?: number }
  >;
  coverage: string;
  dependency_count: number;
  notice: string;
}
export interface Scan {
  id: string;
  repository_id: string;
  name: string;
  status: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  summary: Partial<Summary>;
  error: string | null;
}
export interface Finding {
  id: string;
  scan_id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  priority: Severity;
  priority_score: number;
  priority_reason: string;
  confidence: string;
  file: string;
  line: number | null;
  language: string;
  description: string;
  remediation: string;
  evidence: string;
  cwe: string[];
  owasp: string | null;
  references: string[];
  engines: string[];
  advisory_id: string | null;
  cvss: { type: string; score: string }[];
  source_severity: string | null;
  fingerprint: string;
  suppressed: boolean;
}
export interface Dependency {
  name: string;
  version: string;
  ecosystem: string;
  file: string;
  version_kind: string;
  lookup_status: string;
  advisories: {
    id: string;
    aliases: string[];
    source_severity: string | null;
    cvss: { type: string; score: string }[];
    references: string[];
  }[];
}
export interface Explanation {
  summary: string;
  impact: string;
  concept: string;
  safer_pattern: string;
  proposed_change: string;
  false_positive: string;
  provider: string;
  warning: string | null;
}
export interface Settings {
  fail_on: Severity;
  exposure: "internal" | "internet";
  critical_asset: boolean;
  exclusions: string[];
  ai_provider: string;
  ai_model: string;
  ai_external: boolean;
  allowed_repos: string;
  max_archive_mb: number;
  engines: string;
  deployment_mode: string;
  ai_payload: string;
}
