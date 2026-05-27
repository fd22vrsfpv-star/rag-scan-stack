import ApiTester from './pages/ApiTester'

export default function App() {
  return (
    <div className="h-screen flex flex-col bg-background text-foreground">
      <header className="flex items-center gap-3 px-4 py-2 border-b border-border bg-card/80">
        <span className="text-sm font-bold tracking-tight">API Tester</span>
        <span className="text-[10px] text-muted-foreground">Standalone — Swagger → Burp Suite</span>
      </header>
      <div className="flex-1 overflow-hidden">
        <ApiTester />
      </div>
    </div>
  )
}
