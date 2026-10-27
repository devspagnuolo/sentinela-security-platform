export type ScannerConfig = { enabled: boolean; allowedHosts: string[] };

export function scannerConfig(env: NodeJS.ProcessEnv = process.env): ScannerConfig {
  return {
    enabled: env.SENTINELA_ENABLE_SCANNER === "1",
    allowedHosts: (env.SENTINELA_ALLOWED_HOSTS ?? "").split(",").map(host => host.trim().toLowerCase()).filter(Boolean)
  };
}

export function isHostAllowed(hostname: string, config: ScannerConfig = scannerConfig()): boolean {
  return config.enabled && config.allowedHosts.includes(hostname.toLowerCase());
}
