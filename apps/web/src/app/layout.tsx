import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { title: "Sentinela | Security Assessment", description: "Avaliação defensiva de segurança em escopos autorizados." };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="pt-BR"><body>{children}</body></html>; }
