import { describe, expect, it, vi } from "vitest";
import { awsEncode, CloudError, discoverHosts, groupHosts, signV4, type CloudHttp } from "./cloud";

const reply = (status: number, body: unknown) => ({ status, text: async () => typeof body === "string" ? body : JSON.stringify(body) });

describe("assinatura AWS SigV4", () => {
  it("confere com o exemplo da documentação da AWS (IAM ListUsers)", () => {
    const headers = signV4({
      method: "GET", url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
      headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
      region: "us-east-1", service: "iam", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      now: new Date("2015-08-30T12:36:00Z")
    });
    expect(headers.Authorization).toBe("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
    expect(headers["x-amz-date"]).toBe("20150830T123600Z");
  });

  it("codifica como RFC 3986", () => {
    expect(awsEncode("\\052.example.com. *")).toBe("%5C052.example.com.%20%2A");
  });
});

describe("groupHosts", () => {
  it("junta registros por hostname, ignora curingas e marca hosts só com IP interno", () => {
    const hosts = groupHosts([
      { zone: "example.com.", hostname: "WWW.example.com.", type: "A", target: "93.184.216.34" },
      { zone: "example.com.", hostname: "www.example.com", type: "AAAA", target: "2606:2800:220:1::1" },
      { zone: "example.com.", hostname: "*.example.com", type: "A", target: "93.184.216.34" },
      { zone: "example.com.", hostname: "intranet.example.com", type: "A", target: "10.0.0.5" },
      { zone: "example.com.", hostname: "cdn.example.com", type: "CNAME", target: "d1.cloudfront.net." }
    ]);
    expect(hosts.map(h => [h.hostname, h.recordTypes.join("+"), h.internal])).toEqual([["cdn.example.com", "CNAME", false], ["intranet.example.com", "A", true], ["www.example.com", "A+AAAA", false]]);
    expect(hosts[0].targets).toEqual(["d1.cloudfront.net"]);
  });
});

describe("Cloudflare", () => {
  it("lista zonas e registros com paginação, só por GET e com o token no cabeçalho", async () => {
    const zone = "a".repeat(32);
    const http = vi.fn<CloudHttp>(async url => {
      const u = new URL(url);
      if (u.pathname === "/client/v4/zones") return reply(200, { success: true, result: [{ id: zone, name: "example.com" }], result_info: { page: 1, total_pages: 1 } });
      const page = Number(u.searchParams.get("page"));
      return reply(200, { success: true, result: page === 1 ? [{ name: "www.example.com", type: "A", content: "93.184.216.34" }, { name: "example.com", type: "TXT", content: "v=spf1" }] : [{ name: "api.example.com", type: "CNAME", content: "lb.example.net" }], result_info: { page, total_pages: 2 } });
    });
    const result = await discoverHosts({ provider: "cloudflare", apiToken: "tok" }, { http });
    expect(result).toMatchObject({ zones: 1, hosts: [{ hostname: "api.example.com" }, { hostname: "www.example.com" }] });
    expect(http).toHaveBeenCalledTimes(3);
    for (const [url, headers] of http.mock.calls) {
      expect(new URL(url).hostname).toBe("api.cloudflare.com");
      expect(headers.Authorization).toBe("Bearer tok");
    }
  });

  it("token recusado vira mensagem clara", async () => {
    const http: CloudHttp = async () => reply(403, { success: false, errors: [{ message: "Authentication error" }], result: [] });
    await expect(discoverHosts({ provider: "cloudflare", apiToken: "x" }, { http })).rejects.toThrow("Zone:Read e DNS:Read");
  });
});

describe("AWS Route 53", () => {
  const zonesXml = `<?xml version="1.0"?><ListHostedZonesResponse><HostedZones>
    <HostedZone><Id>/hostedzone/Z1PUB</Id><Name>example.com.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone>
    <HostedZone><Id>/hostedzone/Z2PRIV</Id><Name>corp.internal.</Name><Config><PrivateZone>true</PrivateZone></Config></HostedZone>
  </HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesResponse>`;
  const page1 = `<ListResourceRecordSetsResponse><ResourceRecordSets>
    <ResourceRecordSet><Name>www.example.com.</Name><Type>A</Type><TTL>300</TTL><ResourceRecords><ResourceRecord><Value>93.184.216.34</Value></ResourceRecord></ResourceRecords></ResourceRecordSet>
    <ResourceRecordSet><Name>\\052.example.com.</Name><Type>A</Type><ResourceRecords><ResourceRecord><Value>93.184.216.34</Value></ResourceRecord></ResourceRecords></ResourceRecordSet>
  </ResourceRecordSets><IsTruncated>true</IsTruncated><NextRecordName>shop.example.com.</NextRecordName><NextRecordType>A</NextRecordType></ListResourceRecordSetsResponse>`;
  const page2 = `<ListResourceRecordSetsResponse><ResourceRecordSets>
    <ResourceRecordSet><Name>shop.example.com.</Name><Type>A</Type><AliasTarget><HostedZoneId>Z2</HostedZoneId><DNSName>dualstack.lb-1.us-east-1.elb.amazonaws.com.</DNSName></AliasTarget></ResourceRecordSet>
    <ResourceRecordSet><Name>example.com.</Name><Type>MX</Type><ResourceRecords><ResourceRecord><Value>10 mx.example.com</Value></ResourceRecord></ResourceRecords></ResourceRecordSet>
  </ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>`;

  it("lê zonas públicas, pagina os registros e assina cada chamada", async () => {
    const http = vi.fn<CloudHttp>(async url => {
      const u = new URL(url);
      if (u.pathname.endsWith("/hostedzone")) return reply(200, zonesXml);
      if (u.pathname.includes("Z2PRIV")) throw new Error("zona privada não deve ser lida");
      return reply(200, u.searchParams.get("name") === "shop.example.com." ? page2 : page1);
    });
    const result = await discoverHosts({ provider: "aws_route53", accessKeyId: "AKIAEXAMPLE", secretAccessKey: "s" }, { http, now: () => new Date("2026-10-29T00:00:00Z") });
    expect(result.hosts.map(h => [h.hostname, h.recordTypes[0], h.targets[0]])).toEqual([["shop.example.com", "ALIAS", "dualstack.lb-1.us-east-1.elb.amazonaws.com"], ["www.example.com", "A", "93.184.216.34"]]);
    expect(http).toHaveBeenCalledTimes(3);
    for (const [url, headers] of http.mock.calls) {
      expect(new URL(url).hostname).toBe("route53.amazonaws.com");
      expect(headers.Authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\/20261029\/us-east-1\/route53\/aws4_request, SignedHeaders=host;x-amz-date, Signature=[0-9a-f]{64}$/);
    }
  });

  it("credencial recusada e erro de rede viram CloudError", async () => {
    await expect(discoverHosts({ provider: "aws_route53", accessKeyId: "A", secretAccessKey: "s" }, { http: async () => reply(403, "<ErrorResponse><Error><Message>Denied</Message></Error></ErrorResponse>") })).rejects.toThrow("route53:ListHostedZones");
    await expect(discoverHosts({ provider: "cloudflare", apiToken: "x" }, { http: async () => { throw new Error("ECONNRESET"); } })).rejects.toBeInstanceOf(CloudError);
  });
});
