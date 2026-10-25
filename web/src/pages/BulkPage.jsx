import { useState } from "react";
import { lookupBulk } from "../api.js";

const VCOLOR = {
  MALICIOUS: "text-red-400",
  SUSPICIOUS: "text-amber-400",
  CLEAN: "text-emerald-400",
  UNKNOWN: "text-slate-300",
};

export default function BulkPage() {
  const [text, setText] = useState("");
  const [lang, setLang] = useState("en");
  const [running, setRunning] = useState(false);
  const [out, setOut] = useState(null);

  async function run() {
    const iocs = text.split("\n").map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
    if (!iocs.length) return;
    setRunning(true);
    setOut(null);
    try {
      setOut(await lookupBulk(iocs, lang));
    } catch (e) {
      setOut({ error: e.message });
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="space-y-4">
      <h2 className="font-semibold text-slate-200">Bulk Lookup</h2>
      <div className="bg-panel border border-border rounded-xl p-4 space-y-3">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={8}
          placeholder={"One IOC per line. # = comment.\n8.8.8.8\nevil.com\nhxxp://phish[.]top/login"}
          className="w-full bg-bg border border-border rounded-lg px-4 py-2.5 text-sm font-mono text-slate-200 focus:outline-none focus:border-accent"
        />
        <div className="flex gap-3 items-center">
          <select value={lang} onChange={(e) => setLang(e.target.value)}
                  className="bg-bg border border-border rounded-lg px-3 text-sm text-slate-200">
            <option value="en">EN</option><option value="de">DE</option><option value="id">ID</option>
          </select>
          <button onClick={run} disabled={running || !text.trim()}
                  className="bg-accent hover:bg-cyan-400 disabled:opacity-40 text-slate-900 font-semibold px-6 py-2 rounded-lg text-sm">
            {running ? "Running…" : "Run bulk"}
          </button>
          <span className="text-[11px] text-slate-500">max 50 IOCs · sequential (rate-limit friendly)</span>
        </div>
      </div>

      {running && <div className="text-slate-500 text-sm animate-pulse">⠿ processing batch…</div>}

      {out?.error && <div className="text-red-300 text-sm">{out.error}</div>}

      {out && !out.error && (
        <div className="bg-panel border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 border-b border-border text-xs text-slate-400">
            {out.succeeded}/{out.total} succeeded
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[11px] text-slate-500 border-b border-border">
                <th className="px-4 py-2">IOC</th>
                <th className="px-4 py-2 text-right">Score</th>
                <th className="px-4 py-2">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {out.results.map((r, i) => (
                <tr key={i} className="border-b border-border/50">
                  <td className="px-4 py-2 font-mono text-slate-200">
                    {r.ok ? r.result.ioc.value : r.ioc}
                  </td>
                  {r.ok ? (
                    <>
                      <td className="px-4 py-2 text-right font-mono">{r.result.risk_score}</td>
                      <td className={`px-4 py-2 font-semibold ${VCOLOR[r.result.ai?.verdict] ?? "text-slate-500"}`}>
                        {r.result.ai?.verdict ?? "—"}
                      </td>
                    </>
                  ) : (
                    <td colSpan={2} className="px-4 py-2 text-amber-400 text-xs">invalid: {r.error}</td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
