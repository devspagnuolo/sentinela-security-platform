export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Asset = {
  id: string;
  name: string;
  url: string;
  kind: "Web application" | "API";
  owner: string;
  approved: boolean;
  authorizationRef: string;
  createdAt: string;
};
export type Finding = {
  id: string;
  assetId: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  evidence: string;
  recommendation: string;
  references: string[];
  discoveredAt: string;
};
export type Assessment = { id: string; assetId: string; status: "completed"; startedAt: string; findingIds: string[] };
