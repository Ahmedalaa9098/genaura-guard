export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  patterns: RegExp[];
  fileTypes: string[];
  fix?: string;
  references?: string[];
}

export interface Finding {
  rule: SecurityRule;
  file: string;
  line: number;
  column: number;
  match: string;
  context: string; // The full line of code
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  duration: number;
}

export interface ScanOptions {
  path: string;
  exclude?: string[];
  include?: string[];
  severity?: Severity[];
  fix?: boolean;
  json?: boolean;
  verbose?: boolean;
}

export interface HookConfig {
  enabled: boolean;
  blockOnHigh: boolean;
  blockOnCritical: boolean;
  autoFix: boolean;
}

export interface GuardConfig {
  exclude: string[];
  include: string[];
  severityThreshold: Severity;
  hooks: HookConfig;
  customRules: SecurityRule[];
}

// Sync targets (same as genaura-sync)
export interface SyncTarget {
  name: string;
  path: string;
  filename: string;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'magenta',
  high: 'red',
  medium: 'yellow',
  low: 'blue',
};

export const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '💀',
  high: '✗',
  medium: '⚠',
  low: '○',
};
