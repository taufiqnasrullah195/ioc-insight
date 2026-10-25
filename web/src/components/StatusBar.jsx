import { useEffect, useState } from "react";
import { fetchHealth } from "../api.js";

const POLL_MS = 30_000;

export default function StatusBar() {
  const [health, setHealth] = useState(null);

  async function poll() {
    try {
      setHealth(await fetchHealth());
    } catch {
      setHealth(null); // backend unreachable
    }
  }

  useEffect(() => {
    poll();
    const t = setInterval(poll, POLL_MS);
    return () => clearInterval(t);
  }, []);

  const aiOk = health?.ai?.reachable ?? false;
  const analyzers = health?.analyzers ?? {};

  return (
    <div className="space-y-3">
      {!aiOk && health && (
        <div className="bg-amber-500/10 border border-amber-800/60 text-amber-300 text-xs rounded-lg px-3 py-2">
          ⚠ AI provider unreachable — heuristic verdicts only
        </div>
      )}
      {!health && (
        <div className="bg-red-500/10 border border-red-900/60 text-red-300 text-xs rounded-lg px-3 py-2">
          ✕ API backend unreachable
        </div>
      )}
      <div className="text-[10px] text-slate-600 space-y-1">
        {Object.entries(analyzers).map(([name, s]) => (
          <div key={name} className="flex justify-between">
            <span>{name}</span>
            <span className={s.ready ? "text-emerald-400" : "text-red-400"}>
              {s.ready ? "● ready" : "○ no key"}
            </span>
          </div>
        ))}
        <div className="flex justify-between">
          <span>ai ({health?.ai?.model ?? "…"})</span>
          <span className={aiOk ? "text-emerald-400" : "text-red-400"}>
            {health ? (aiOk ? "● online" : "○ down") : "…"}
          </span>
        </div>
      </div>
    </div>
  );
}
