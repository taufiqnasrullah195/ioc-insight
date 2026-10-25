import { useState } from "react";
import LookupPage from "./pages/LookupPage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import StatusBar from "./components/StatusBar.jsx";

export default function App() {
  const [page, setPage] = useState("lookup");

  return (
    <div className="min-h-screen bg-bg text-slate-200 flex">
      {/* Sidebar */}
      <aside className="w-56 shrink-0 bg-panel border-r border-border p-4 flex flex-col min-h-screen">
        <div className="flex items-center gap-2 mb-8">
          <div className="w-8 h-8 rounded-lg bg-accent/20 flex items-center justify-center text-accent font-bold">◉</div>
          <div>
            <div className="font-bold text-sm">IOC Insight</div>
            <div className="text-[10px] text-slate-500">SOC L1 Triage</div>
          </div>
        </div>
        <nav className="space-y-1 text-sm">
          {[["lookup", "⌕ Lookup"], ["history", "🗂 History"]].map(([key, label]) => (
            <button key={key}
                    onClick={() => setPage(key)}
                    className={`w-full text-left px-3 py-2 rounded-lg ${page === key ? "bg-accent/10 text-accent" : "text-slate-400 hover:bg-slate-800/50"}`}>
              {label}
            </button>
          ))}
        </nav>
        <div className="mt-auto">
          <StatusBar />
          <div className="mt-3 text-[10px] text-slate-700">built by TheWiseParadise</div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 p-6 max-w-6xl">
        {page === "lookup" ? <LookupPage /> : <HistoryPage />}
      </main>
    </div>
  );
}
