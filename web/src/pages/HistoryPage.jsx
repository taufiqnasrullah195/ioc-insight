import { useEffect, useState } from "react";
import { fetchHistory, fetchHistoryItem } from "../api.js";
import VerdictCard from "../components/VerdictCard.jsx";
import SourceCards from "../components/SourceCards.jsx";
import ReportPanel from "../components/ReportPanel.jsx";

const VCOLOR = {
  MALICIOUS: "text-red-400",
  SUSPICIOUS: "text-amber-400",
  CLEAN: "text-emerald-400",
  UNKNOWN: "text-slate-300",
};

export default function HistoryPage() {
  const [data, setData] = useState({ items: [], total: 0 });
  const [offset, setOffset] = useState(0);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);
  const LIMIT = 20;

  async function load(off = offset) {
    try {
      setData(await fetchHistory(LIMIT, off));
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }

  useEffect(() => { load(0); }, []);

  async function openDetail(id) {
    try {
      setDetail(await fetchHistoryItem(id));
    } catch (e) {
      setError(e.message);
    }
  }

  const pages = Math.ceil(data.total / LIMIT);
  const page = Math.floor(offset / LIMIT) + 1;

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="font-semibold text-slate-200">History — {data.total} lookups</h2>
        <button onClick={() => load()} className="text-xs bg-panel border border-border px-3 py-1.5 rounded-lg hover:border-accent text-slate-300">
          ↻ Refresh
        </button>
      </div>

      {error && <div className="text-red-300 text-sm">{error}</div>}

      {data.items.length === 0 && !error && (
        <div className="text-center text-slate-600 py-16 text-sm">No lookups yet — run one from the Lookup page.</div>
      )}

      {data.items.length > 0 && (
        <div className="bg-panel border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[11px] text-slate-500 border-b border-border">
                <th className="px-4 py-2.5">#</th>
                <th className="px-4 py-2.5">IOC</th>
                <th className="px-4 py-2.5">Type</th>
                <th className="px-4 py-2.5 text-right">Score</th>
                <th className="px-4 py-2.5">Verdict</th>
                <th className="px-4 py-2.5">Lang</th>
                <th className="px-4 py-2.5 text-right">When</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((it) => (
                <tr key={it.id}
                    onClick={() => openDetail(it.id)}
                    className="border-b border-border/50 hover:bg-slate-800/40 cursor-pointer">
                  <td className="px-4 py-2.5 text-slate-500 font-mono">{it.id}</td>
                  <td className="px-4 py-2.5 font-mono text-slate-200">{it.ioc_value}</td>
                  <td className="px-4 py-2.5 text-slate-400">{it.ioc_type}</td>
                  <td className="px-4 py-2.5 text-right font-mono">{it.risk_score}</td>
                  <td className={`px-4 py-2.5 font-semibold ${VCOLOR[it.verdict] ?? "text-slate-500"}`}>
                    {it.verdict ?? "—"}
                  </td>
                  <td className="px-4 py-2.5 text-slate-400">{it.lang ?? "—"}</td>
                  <td className="px-4 py-2.5 text-right text-slate-500 text-xs">
                    {new Date(it.created_at * 1000).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {pages > 1 && (
        <div className="flex gap-2 justify-center text-xs">
          <button disabled={offset === 0}
                  onClick={() => { const o = Math.max(0, offset - LIMIT); setOffset(o); load(o); }}
                  className="bg-panel border border-border px-3 py-1.5 rounded-lg disabled:opacity-40">← Prev</button>
          <span className="px-3 py-1.5 text-slate-500">page {page}/{pages}</span>
          <button disabled={offset + LIMIT >= data.total}
                  onClick={() => { const o = offset + LIMIT; setOffset(o); load(o); }}
                  className="bg-panel border border-border px-3 py-1.5 rounded-lg disabled:opacity-40">Next →</button>
        </div>
      )}

      {detail && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center p-6 z-50"
             onClick={() => setDetail(null)}>
          <div className="bg-bg border border-border rounded-xl max-w-4xl w-full max-h-[85vh] overflow-auto p-6 space-y-6"
               onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between items-center">
              <span className="font-mono text-slate-300">{detail.ioc.value}</span>
              <button onClick={() => setDetail(null)} className="text-slate-500 hover:text-slate-200">✕ close</button>
            </div>
            <div className="grid grid-cols-3 gap-6">
              <div className="col-span-2 space-y-6">
                <VerdictCard result={detail} />
                <SourceCards results={detail.analyzer_results} />
              </div>
              <ReportPanel
                report={detail.ai?.report_markdown}
                model={detail.ai?.model}
                lang={detail.ai?.lang}
                durationMs={detail.duration_ms}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
