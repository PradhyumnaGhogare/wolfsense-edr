import type { Metadata } from "next";

import { Sidebar } from "../components/sidebar";
import "./globals.css";

export const metadata: Metadata = {
  title: "WolfSense SOC",
  description: "EDR and SOC operations dashboard for endpoint telemetry, detections, and incidents.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <div className="mx-auto grid min-h-screen max-w-[1600px] gap-6 px-4 py-6 lg:grid-cols-[300px_1fr]">
          <Sidebar />
          <main className="space-y-6">{children}</main>
        </div>
      </body>
    </html>
  );
}
