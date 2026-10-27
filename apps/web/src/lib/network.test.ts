import { describe, expect, it } from "vitest";
import { isPublicAddress } from "./network";

describe("isPublicAddress", () => {
  it.each(["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"])("aceita endereço público %s", ip => {
    expect(isPublicAddress(ip)).toBe(true);
  });

  it.each([
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "0.0.0.0", "224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.2.10", "203.0.113.5",
    "::", "::1", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8",
    "64:ff9b::a00:1", "2002:a00:1::", "2001:db8::1"
  ])("bloqueia endereço não público %s", ip => {
    expect(isPublicAddress(ip)).toBe(false);
  });

  it("rejeita valores que não são IP", () => {
    expect(isPublicAddress("example.com")).toBe(false);
    expect(isPublicAddress("")).toBe(false);
  });
});
