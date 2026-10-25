import { ACTION_LABEL, VERDICT_BG, VERDICT_COLORS } from "../lib/ioc.js";

export default function VerdictCard({ result }) {
  const ai = result.ai;
  const verdict = ai?.verdict ?? "UNKNOWN";
  const colors = VERDICT_COLORS[verdict] || VERDICT_COLORS.UNKNOWN;
  const barBg = VERDICT_BG[verdict] || VERDICT_BG.UNKNOWN;

  return (
    <div className={`bg-panel border rounded-xl p-5 ${colors.split(" ")[1]}`}>
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <div className="flex items-center gap-3">
            <span className={`text-2xl font-bold ${colors.split(" ")[0]}`}>{verdict}</span>
            {ai && (
              <span className="text-xs bg-slate-800 text-slate-300 px-2 py-1 rounded-full">
                confidence {ai.confidence}%
              </span>
            )}
            {ai?.model === "heuristic-fallback" && (
              <span className="text-xs bg-amber-500/15 text-amber-300 px-2 py-1 rounded-full">
                heuristic (AI unavailable)
              </span>
            )}
          </div>
          <div className="mt-2 text-xs text-slate-400">Composite risk score</div>
          <div className="flex items-center gap-3 mt-1">
            <div className="w-56 h-2 bg-slate-800 rounded-full overflow-hidden">
              <div className={`h-full bg-gradient-to-r ${barBg}`}
                   style={{ width: `${result.risk_score}%` }} />
            </div>
            <span className="font-mono text-lg font-bold text-slate-200">
              {result.risk_score}<span className="text-slate-500 text-xs">/100</span>
            </span>
          </div>
        </div>
        {ai && (
          <div className="text-right">
            <div className="text-[11px] text-slate-500">Recommended action</div>
            <div className="mt-1 inline-block bg-slate-800 border border-border text-slate-200 text-xs font-semibold px-3 py-1.5 rounded-lg">
              {ACTION_LABEL[ai.recommended_action] ?? ai.recommended_action}
            </div>
          </div>
        )}
      </div>
      {ai && <p className="mt-4 text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">{ai.explanation}</p>}
      <div className="mt-3 flex gap-2 text-[11px] flex-wrap">
        {result.analyzer_results.flatMap((r) => r.tags).slice(0, 8).map((t) => (
          <span key={t} className="bg-slate-800 px-2 py-1 rounded font-mono text-slate-300">{t}</span>
        ))}
      </div>
      {result.mitre?.length > 0 && (
        <div className="mt-3 pt-3 border-t border-border">
          <div className="text-[10px] text-slate-500 mb-1.5">MITRE ATT&CK</div>
          <div className="flex gap-2 flex-wrap">
            {result.mitre.map((t) => (
              <span key={t.id} title={t.sources.join(", ")}
                    className="text-[11px] bg-purple-500/10 text-purple-300 border border-purple-500/30 px-2 py-1 rounded font-mono">
                {t.id} {t.name}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
