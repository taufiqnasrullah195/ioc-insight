import { useState } from "react";

export default function ReportPanel({ report, model, lang, durationMs }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard API unavailable — user can select manually */
    }
  }

  if (!report) return null;
  return (
    <div className="bg-panel border border-border rounded-xl p-4 flex flex-col h-full">
      <div className="flex justify-between items-center mb-3">
        <span className="font-semibold text-sm text-slate-200">📋 Ticket Report</span>
        <button onClick={copy}
                className="text-xs bg-accent/15 text-accent px-3 py-1.5 rounded-lg border border-accent/30 hover:bg-accent/25">
          {copied ? "✓ copied" : "Copy markdown"}
        </button>
      </div>
      <pre className="font-mono text-[11px] text-slate-400 bg-bg border border-border rounded-lg p-3 flex-1 overflow-auto whitespace-pre-wrap">
        {report}
      </pre>
      <div className="mt-3 text-[10px] text-slate-600">
        {model} · {lang} · {durationMs}ms
      </div>
    </div>
  );
}
