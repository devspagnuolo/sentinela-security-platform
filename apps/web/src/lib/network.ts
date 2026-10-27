import { BlockList, isIP } from "node:net";

// Faixas que o scanner nunca deve alcançar: privadas, loopback, link-local,
// CGNAT, documentação, benchmark, multicast, reservadas e mecanismos de transição.
// Listas separadas: o BlockList do Node aplica regras IPv6 a IPv4 mapeado, e vice-versa.
const blockedV4 = new BlockList();
const blockedV6 = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]
] as const) blockedV4.addSubnet(network, prefix, "ipv4");
for (const [network, prefix] of [
  ["::", 128], ["::1", 128], ["64:ff9b::", 96], ["64:ff9b:1::", 48], ["100::", 64],
  ["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8]
] as const) blockedV6.addSubnet(network, prefix, "ipv6");

/** Retorna true somente para endereços IP unicast públicos e roteáveis. */
export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !blockedV4.check(address, "ipv4");
  if (family === 6) {
    // IPv4 mapeado/compatível (::ffff:a.b.c.d, ::a.b.c.d) é sempre recusado; a forma normalizada evita variações de escrita.
    const normalized = new URL(`http://[${address}]`).hostname.slice(1, -1);
    if (/^::(ffff:)?[0-9a-f]{1,4}:[0-9a-f]{1,4}$/.test(normalized)) return false;
    return !blockedV6.check(address, "ipv6");
  }
  return false;
}
