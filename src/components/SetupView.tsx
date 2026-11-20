import React, { useState } from 'react';
import { ShieldCheck, Terminal, KeyRound, Lock } from 'lucide-react';
import { api } from '../api';
import type { AppSettings, User } from '../types';

interface SetupViewProps {
  onComplete: (user: User, settings: AppSettings) => void;
}

export function SetupView({ onComplete }: SetupViewProps) {
  const [instanceName, setInstanceName] = useState('SSH Console');
  const [username, setUsername] = useState('admin');
  const [displayName, setDisplayName] = useState('Administrator');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError('Das Passwort muss mindestens 8 Zeichen umfassen.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Die beiden Passwort-Eingaben stimmen nicht überein.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await api.setupAdmin({
        username,
        displayName,
        password,
        instanceName,
      });
      onComplete(res.user, res.settings);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ersteinrichtung fehlgeschlagen.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      <header className="border-b border-slate-200 bg-white px-8 py-4 flex items-center justify-between gap-8">
        <span className="font-display text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0">
          SSH Console
        </span>
        <span className="text-xs text-slate-500 whitespace-nowrap shrink-0">
          Debian 13 (Trixie) · Ersteinrichtung
        </span>
      </header>

      <main className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 gap-10 items-stretch">
          <section className="lg:col-span-6 flex flex-col justify-between py-2">
            <div>
              <p className="text-xs font-medium text-blue-700 mb-3">
                Einmalige Systeminitialisierung
              </p>
              <h1 className="font-display text-3xl sm:text-4xl font-bold tracking-tight text-slate-900 leading-tight">
                Administrator-Konto für SSH Console einrichten
              </h1>
              <p className="mt-4 text-sm sm:text-base text-slate-600 leading-relaxed max-w-xl">
                Legen Sie das erste Administratorkonto fest. Nach Abschluss dieser Einrichtung wird die
                Setup-Route dauerhaft gesperrt — eine öffentliche Selbstregistrierung existiert nicht.
              </p>

              <div className="mt-8 space-y-5 border-t border-slate-200 pt-6">
                <div className="flex items-start gap-3.5">
                  <ShieldCheck className="w-5 h-5 text-slate-700 shrink-0 mt-0.5" />
                  <div>
                    <h2 className="text-sm font-semibold text-slate-900">
                      01. Zentrale Befehlsfreigabe
                    </h2>
                    <p className="text-sm text-slate-600 mt-0.5">
                      Der Administrator definiert freigegebene SSH-Befehle. Benutzer wählen ausschließlich aus dieser Liste.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3.5">
                  <KeyRound className="w-5 h-5 text-slate-700 shrink-0 mt-0.5" />
                  <div>
                    <h2 className="text-sm font-semibold text-slate-900">
                      02. Passwortlose OpenSSH-Zertifikate
                    </h2>
                    <p className="text-sm text-slate-600 mt-0.5">
                      Unterstützt das vollständige 3-Dateien-Modell aus{' '}
                      <code className="font-mono text-xs text-slate-800">zertifikat</code>,{' '}
                      <code className="font-mono text-xs text-slate-800">zertifikat.pub</code> und{' '}
                      <code className="font-mono text-xs text-slate-800">zertifikat-cert.pub</code>.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3.5">
                  <Terminal className="w-5 h-5 text-slate-700 shrink-0 mt-0.5" />
                  <div>
                    <h2 className="text-sm font-semibold text-slate-900">
                      03. Rust-Backend für Debian Trixie
                    </h2>
                    <p className="text-sm text-slate-600 mt-0.5">
                      Inklusive vollständigem Rust-Quellcode (Axum, SQLite, Argon2, AES-256-GCM), systemd-Unit und Installationsskript.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-8 pt-6 border-t border-slate-200 flex items-center gap-2 text-xs text-slate-500">
              <Lock className="w-3.5 h-3.5 shrink-0" />
              <span>Private Schlüssel werden verschlüsselt gespeichert und nur für die Dauer der SSH-Sitzung (0600) bereitgestellt.</span>
            </div>
          </section>

          <section className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-8 flex flex-col justify-center">
            <h2 className="font-display text-lg font-semibold text-slate-900">
              Ersten Administrator erstellen
            </h2>
            <p className="text-sm text-slate-500 mt-1">
              Alle Felder können später in der Benutzerverwaltung angepasst werden.
            </p>

            {error && (
              <div
                role="alert"
                className="mt-5 px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800"
              >
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="mt-6 space-y-4">
              <div>
                <label htmlFor="setup-instance" className="block text-sm font-medium text-slate-700 mb-1.5">
                  Instanzbezeichnung
                </label>
                <input
                  id="setup-instance"
                  type="text"
                  value={instanceName}
                  onChange={(e) => setInstanceName(e.target.value)}
                  placeholder="z. B. SSH Console Produktion"
                  className="w-full px-3.5 py-2.5 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  required
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="setup-username" className="block text-sm font-medium text-slate-700 mb-1.5">
                    Admin-Benutzername
                  </label>
                  <input
                    id="setup-username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="admin"
                    autoComplete="username"
                    className="w-full px-3.5 py-2.5 text-sm font-mono bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    required
                  />
                </div>
                <div>
                  <label htmlFor="setup-display" className="block text-sm font-medium text-slate-700 mb-1.5">
                    Anzeigename
                  </label>
                  <input
                    id="setup-display"
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="Systemadministrator"
                    className="w-full px-3.5 py-2.5 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    required
                  />
                </div>
              </div>

              <div>
                <label htmlFor="setup-password" className="block text-sm font-medium text-slate-700 mb-1.5">
                  Passwort (mindestens 8 Zeichen)
                </label>
                <input
                  id="setup-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  className="w-full px-3.5 py-2.5 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  required
                  minLength={8}
                />
              </div>

              <div>
                <label htmlFor="setup-password-confirm" className="block text-sm font-medium text-slate-700 mb-1.5">
                  Passwort bestätigen
                </label>
                <input
                  id="setup-password-confirm"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  autoComplete="new-password"
                  className="w-full px-3.5 py-2.5 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  required
                  minLength={8}
                />
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full py-2.5 px-4 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                >
                  {submitting ? 'Einrichtung wird abgeschlossen...' : 'Ersteinrichtung abschließen'}
                </button>
              </div>
            </form>
          </section>
        </div>
      </main>
    </div>
  );
}
