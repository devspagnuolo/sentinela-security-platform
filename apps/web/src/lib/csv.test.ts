import { describe, expect, it } from "vitest";
import { csvCell, toCsv } from "./csv";

describe("csv", () => {
  it("escapa aspas e neutraliza fórmulas", () => {
    expect(csvCell('a "b"')).toBe('"a ""b"""');
    expect(csvCell("=HYPERLINK(\"x\")")).toBe('"\'=HYPERLINK(""x"")"');
    expect(csvCell("+1")).toBe('"\'+1"');
    expect(csvCell("-2")).toBe('"\'-2"');
    expect(csvCell("@SUM(A1)")).toBe('"\'@SUM(A1)"');
    expect(csvCell(null)).toBe('""');
    expect(csvCell({ a: 1 })).toBe('"{""a"":1}"');
  });
  it("monta linhas com BOM para o Excel reconhecer UTF-8", () => {
    expect(toCsv([["a", "b"], [1, "ç"]])).toBe('﻿"a","b"\r\n"1","ç"');
  });
});
