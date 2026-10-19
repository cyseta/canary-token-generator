import React, { useState, useEffect } from 'react';
import { LandingPage } from './pages/landing/LandingPage';
import { ManagePage } from './pages/manage/ManagePage';
import { Shield, Radio, Terminal } from 'lucide-react';

// Formato de la clave de gestión: 'k' + 32 hex. Cualquier otro valor se ignora.
const MANAGE_KEY_RE = /^k[0-9a-f]{32}$/;

export const App: React.FC = () => {
  const [manageKey, setManageKey] = useState<string | null>(null);

  const [daemonOnline, setDaemonOnline] = useState<boolean | null>(null);

  useEffect(() => {
    // Estado REAL del daemon (antes el indicador "Daemon Online" era un texto fijo).
    let cancelled = false;
    const check = () =>
      fetch('/healthz', { cache: 'no-store' })
        .then((r) => !cancelled && setDaemonOnline(r.ok))
        .catch(() => !cancelled && setDaemonOnline(false));
    check();
    const id = window.setInterval(check, 30000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  useEffect(() => {
    const handleLocation = () => {
      const hash = window.location.hash;
      const path = window.location.pathname;

      if (hash.startsWith('#/manage/')) {
        const key = hash.replace('#/manage/', '');
        setManageKey(MANAGE_KEY_RE.test(key) ? key : null);
      } else if (path.startsWith('/manage/')) {
        // Enlace antiguo con la clave en la ruta: se mueve al fragmento (que no se envía a servidores ni logs).
        const key = path.replace('/manage/', '');
        if (MANAGE_KEY_RE.test(key)) {
          window.history.replaceState(null, '', `/#/manage/${key}`);
          setManageKey(key);
        } else {
          setManageKey(null);
        }
      } else {
        setManageKey(null);
      }
    };

    handleLocation();
    window.addEventListener('hashchange', handleLocation);
    window.addEventListener('popstate', handleLocation);
    return () => {
      window.removeEventListener('hashchange', handleLocation);
      window.removeEventListener('popstate', handleLocation);
    };
  }, []);

  const navigateToManage = (key: string) => {
    window.location.hash = `#/manage/${key}`;
    setManageKey(key);
  };

  const navigateToHome = () => {
    window.location.hash = '';
    setManageKey(null);
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      {/* Navigation Bar */}
      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <div 
            onClick={navigateToHome} 
            className="flex items-center gap-2.5 cursor-pointer group"
          >
            <div className="w-8 h-8 rounded-lg bg-yellow-500/10 border border-yellow-500/40 flex items-center justify-center text-yellow-400 group-hover:bg-yellow-500/20 transition">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <span className="font-extrabold text-base tracking-tight text-white group-hover:text-yellow-400 transition">
                CANARY<span className="text-yellow-500">TOKENS</span>
              </span>
              <span className="hidden sm:inline-block ml-2 text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                Early Warning Trap
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs font-semibold">
            <div
              className={`flex items-center gap-2 px-2.5 py-1 rounded-full border ${
                daemonOnline === false
                  ? 'text-red-400 bg-red-500/10 border-red-500/20'
                  : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
              }`}
            >
              <Radio className={`w-3.5 h-3.5 ${daemonOnline === false ? '' : 'animate-pulse'}`} />
              <span>{daemonOnline === null ? 'Checking…' : daemonOnline ? 'Daemon Online' : 'Daemon Offline'}</span>
            </div>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-400 hover:text-slate-200 transition hidden sm:inline"
            >
              Docs & Guide
            </a>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1">
        {manageKey ? (
          <ManagePage manageKey={manageKey} onBack={navigateToHome} />
        ) : (
          <LandingPage onNavigateManage={navigateToManage} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs text-slate-500">
        <div className="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>Canary Token Intrusion Detection System — Open Source Cyber Deception</div>
          <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px]">
            <span>TCP 3306 (MySQL)</span>
            <span>•</span>
            <span>HTTP 8080 (Sensors)</span>
            <span>•</span>
            <span>K8s Wildcard</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
