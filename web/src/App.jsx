import LookupPage from "./pages/LookupPage.jsx";

export default function App() {
  return (
    <div className="min-h-screen bg-bg text-slate-200">
      <header className="border-b border-border px-6 py-4 flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-accent/20 flex items-center justify-center text-accent font-bold">◉</div>
        <div>
          <div className="font-bold text-sm">IOC Insight</div>
          <div className="text-[10px] text-slate-500">SOC L1 Triage · built by TheWiseParadise</div>
        </div>
      </header>
      <main className="p-6 max-w-7xl mx-auto">
        <LookupPage />
      </main>
    </div>
  );
}
