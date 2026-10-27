/**
 * Gera CSV (RFC 4180) seguro para planilhas: células que começam com = + - @
 * ou caracteres de controle recebem um apóstrofo, evitando injeção de fórmulas
 * com dados vindos de alvos avaliados ou de usuários.
 */
export function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? "" : typeof value === "object" ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

export const toCsv = (rows: unknown[][]) => "﻿" + rows.map(row => row.map(csvCell).join(",")).join("\r\n");
