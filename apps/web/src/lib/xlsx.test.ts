import { inflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { buildXlsx } from "./xlsx";

/** Lê as entradas de um ZIP pelos cabeçalhos locais (suficiente para o que buildXlsx gera). */
function unzip(buf: Buffer) {
  const files = new Map<string, string>();
  for (let at = 0; buf.readUInt32LE(at) === 0x04034b50;) {
    const size = buf.readUInt32LE(at + 18), nameLength = buf.readUInt16LE(at + 26), extra = buf.readUInt16LE(at + 28);
    const name = buf.subarray(at + 30, at + 30 + nameLength).toString("utf8");
    const start = at + 30 + nameLength + extra;
    files.set(name, inflateRawSync(buf.subarray(start, start + size)).toString("utf8"));
    at = start + size;
  }
  return files;
}

describe("buildXlsx", () => {
  const columns = Array.from({ length: 28 }, (_, i) => ({ header: `C${i}` }));
  const files = unzip(buildXlsx([{ name: "Achados: [teste]", columns, rows: [["=HYPERLINK(\"http://x\")", 42, null, "a & <b>\u0007"]] }]));

  it("gera o pacote OOXML com workbook, estilos e planilhas", () => {
    expect([...files.keys()]).toEqual(["[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/worksheets/sheet1.xml"]);
    expect(files.get("xl/workbook.xml")).toContain('name="Achados   teste "');
  });

  it("texto vira inlineStr (nunca fórmula), números ficam numéricos e caracteres inválidos somem", () => {
    const sheet = files.get("xl/worksheets/sheet1.xml")!;
    expect(sheet).toContain('<c r="A2" s="2" t="inlineStr"><is><t xml:space="preserve">=HYPERLINK(&quot;http://x&quot;)</t></is></c>');
    expect(sheet).not.toContain("<f>");
    expect(sheet).toContain('<c r="B2" s="2"><v>42</v></c>');
    expect(sheet).not.toContain('r="C2"');
    expect(sheet).toContain("a &amp; &lt;b&gt;</t>");
    expect(sheet).not.toContain("\u0007");
  });

  it("nomeia colunas depois de Z e congela o cabeçalho com filtro", () => {
    const sheet = files.get("xl/worksheets/sheet1.xml")!;
    expect(sheet).toContain('r="AB1"');
    expect(sheet).toContain('<autoFilter ref="A1:AB2"/>');
    expect(sheet).toContain('state="frozen"');
  });
});
