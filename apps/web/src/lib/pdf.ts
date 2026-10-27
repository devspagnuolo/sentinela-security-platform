import { PDFDocument, rgb, StandardFonts, type PDFFont, type PDFPage, type RGB } from "pdf-lib";
import { FINDING_STATUS_LABELS, SCOPE_STATE_LABELS, SEVERITY_LABELS } from "./labels";
import { SEVERITY_ORDER, type Report } from "./report";
import type { Severity } from "./types";

const A4: [number, number] = [595.28, 841.89];
const MARGIN = 50;
const WIDTH = A4[0] - MARGIN * 2;
const GREEN = rgb(0.09, 0.42, 0.33), INK = rgb(0.09, 0.19, 0.15), MUTED = rgb(0.38, 0.45, 0.42), LINE = rgb(0.86, 0.91, 0.88);
const SEVERITY_COLORS: Record<Severity, RGB> = { critical: rgb(0.79, 0.27, 0.25), high: rgb(0.85, 0.47, 0.29), medium: rgb(0.72, 0.56, 0.13), low: rgb(0.29, 0.59, 0.43), info: rgb(0.4, 0.5, 0.69) };
const date = (iso: string | null) => iso ? new Date(iso).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", dateStyle: "short", timeStyle: "short" }) : "—";

/** Escreve de cima para baixo, quebrando linhas pela largura real do texto e abrindo páginas quando precisa. */
class Writer {
  page!: PDFPage;
  y = 0;
  private readonly supported: Set<number>;
  constructor(readonly doc: PDFDocument, readonly regular: PDFFont, readonly bold: PDFFont) {
    this.supported = new Set(regular.getCharacterSet());
    this.newPage();
  }
  newPage() { this.page = this.doc.addPage(A4); this.y = A4[1] - MARGIN; }
  ensure(height: number) { if (this.y - height < MARGIN + 20) this.newPage(); }

  /** As fontes padrão do PDF cobrem Latin-1/WinAnsi (acentos do português); o resto vira equivalente ou "?". */
  clean(text: string) {
    return [...text.replace(/[→⇒]/g, "->").replace(/[\t\r]/g, " ")].map(ch => ch === "\n" || this.supported.has(ch.codePointAt(0)!) ? ch : "?").join("");
  }

  wrap(text: string, font: PDFFont, size: number, width: number) {
    const lines: string[] = [];
    for (const paragraph of this.clean(text).split("\n")) {
      let line = "";
      for (const word of paragraph.split(/ +/)) {
        const candidate = line ? `${line} ${word}` : word;
        if (font.widthOfTextAtSize(candidate, size) <= width) { line = candidate; continue; }
        if (line) lines.push(line);
        // Palavra maior que a linha (URLs, hashes): quebra por caractere.
        line = "";
        for (const ch of word) {
          if (font.widthOfTextAtSize(line + ch, size) > width && line) { lines.push(line); line = ""; }
          line += ch;
        }
      }
      lines.push(line);
    }
    return lines;
  }

  text(text: string, opts: { size?: number; font?: PDFFont; color?: RGB; indent?: number; gap?: number } = {}) {
    const size = opts.size ?? 10, font = opts.font ?? this.regular, indent = opts.indent ?? 0, leading = size * 1.35;
    for (const line of this.wrap(text, font, size, WIDTH - indent)) {
      this.ensure(leading);
      this.page.drawText(line, { x: MARGIN + indent, y: this.y - size, size, font, color: opts.color ?? INK });
      this.y -= leading;
    }
    this.y -= opts.gap ?? 4;
  }

  /** "Rótulo: valor" com o rótulo em negrito na primeira linha. */
  field(label: string, value: string, indent = 0) {
    const size = 10, labelText = this.clean(`${label}: `), labelWidth = this.bold.widthOfTextAtSize(labelText, size);
    const [first, ...rest] = this.wrap(value || "—", this.regular, size, WIDTH - indent - labelWidth);
    this.ensure(size * 1.35);
    this.page.drawText(labelText, { x: MARGIN + indent, y: this.y - size, size, font: this.bold, color: INK });
    this.page.drawText(first, { x: MARGIN + indent + labelWidth, y: this.y - size, size, font: this.regular, color: INK });
    this.y -= size * 1.35;
    if (rest.length) this.text(rest.join(" "), { indent: indent + labelWidth, gap: 0 });
    this.y -= 2;
  }

  heading(text: string) {
    this.ensure(40);
    this.y -= 10;
    this.text(text, { size: 14, font: this.bold, color: GREEN, gap: 2 });
    this.page.drawLine({ start: { x: MARGIN, y: this.y }, end: { x: MARGIN + WIDTH, y: this.y }, thickness: 0.6, color: LINE });
    this.y -= 8;
  }

  tag(label: string, color: RGB, x: number, y: number) {
    const size = 8, width = this.bold.widthOfTextAtSize(label, size) + 10;
    this.page.drawRectangle({ x, y: y - 3, width, height: size + 6, color, opacity: 0.15 });
    this.page.drawText(label, { x: x + 5, y, size, font: this.bold, color });
    return width;
  }
}

/** PDF do relatório, gerado no servidor com as fontes padrão (nenhum recurso externo é carregado). */
export async function renderPdf(report: Report): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.setTitle(`Relatório de segurança - ${report.asset.name}`);
  doc.setAuthor("Sentinela");
  doc.setSubject(report.classification);
  doc.setProducer("Sentinela");
  doc.setCreator("Sentinela");
  doc.setCreationDate(new Date(report.generatedAt));
  const w = new Writer(doc, await doc.embedFont(StandardFonts.Helvetica), await doc.embedFont(StandardFonts.HelveticaBold));

  // Capa resumida
  w.page.drawRectangle({ x: 0, y: A4[1] - 8, width: A4[0], height: 8, color: GREEN });
  w.text("Relatório de avaliação de segurança", { size: 20, font: w.bold, color: GREEN, gap: 2 });
  w.text(`${report.classification}${report.demonstration ? " · DADOS DEMONSTRATIVOS" : ""}`, { color: MUTED, gap: 2 });
  w.text(`Gerado em ${date(report.generatedAt)}`, { size: 9, color: MUTED, gap: 8 });

  w.heading("Escopo e autorização");
  w.field("Ativo", `${report.asset.name} (${report.asset.url})`);
  w.field("Tipo", report.asset.kind);
  w.field("Responsável", report.asset.owner);
  w.field("Referência da autorização", report.authorization.reference);
  w.field("Situação da autorização", report.authorization.state ? SCOPE_STATE_LABELS[report.authorization.state] : "Sem escopo vinculado");
  w.field("Autorização válida até", date(report.authorization.validUntil));

  const { method } = report.assessment;
  w.heading("Método utilizado");
  w.field("Método", `${method.name} (${method.id})`);
  w.field("Execução", `${date(report.assessment.startedAt)} · ${report.assessment.id}`);
  w.text(method.request);
  if (method.checks.length) w.field("Verificações", method.checks.join(", "));
  if (method.exclusions.length) w.field("Fora do escopo", method.exclusions.join(", "));

  w.heading("Resumo de riscos");
  w.ensure(30);
  let x = MARGIN;
  for (const severity of SEVERITY_ORDER) x += w.tag(`${SEVERITY_LABELS[severity]}: ${report.summary.bySeverity[severity] ?? 0}`, SEVERITY_COLORS[severity], x, w.y - 10) + 6;
  w.y -= 24;
  w.text(`${report.summary.total} achado(s) observados nesta execução. Classificação automática preliminar; revisão humana obrigatória.`, { color: MUTED });

  w.heading("Achados técnicos");
  if (!report.findings.length) w.text("Nenhum achado nesta avaliação limitada.");
  report.findings.forEach((f, i) => {
    w.ensure(70);
    w.text(`${i + 1}. ${f.title}`, { size: 11.5, font: w.bold, gap: 1 });
    w.ensure(16);
    let tx = MARGIN;
    tx += w.tag(SEVERITY_LABELS[f.severity], SEVERITY_COLORS[f.severity], tx, w.y - 9) + 5;
    tx += w.tag(FINDING_STATUS_LABELS[f.status], MUTED, tx, w.y - 9) + 5;
    w.page.drawText(w.clean(f.category), { x: tx + 2, y: w.y - 9, size: 8.5, font: w.regular, color: MUTED });
    w.y -= 18;
    if (f.statusReason && f.status !== "open") w.field("Triagem", f.statusReason, 8);
    w.field("Observação", f.observation, 8);
    w.field("Evidência", f.evidence, 8);
    w.field("Risco potencial", f.potentialRisk, 8);
    w.field("Recomendação", f.recommendation, 8);
    if (f.references.length) w.field("Referências", f.references.join(", "), 8);
    w.y -= 6;
  });

  w.heading("Limitações");
  w.text(report.limitations);

  // Rodapé com paginação, depois que o total de páginas é conhecido.
  const pages = doc.getPages();
  pages.forEach((page, i) => {
    const footer = w.clean(`Sentinela · ${report.asset.name} · Execução ${report.assessment.id.slice(0, 8)} · Página ${i + 1} de ${pages.length}`);
    page.drawText(footer, { x: MARGIN, y: MARGIN - 20, size: 8, font: w.regular, color: MUTED });
  });
  return doc.save();
}
