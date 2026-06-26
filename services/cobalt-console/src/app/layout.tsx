'use client';

import './globals.css';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

const navigation = [
  { name: 'Dashboard', href: '/', icon: '◉' },
  { name: 'Incidents', href: '/incidents', icon: '⚠' },
  { name: 'Agents', href: '/agents', icon: '◈' },
  { name: 'Settings', href: '/settings', icon: '⚙' },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-dark-900 text-white font-sans">
        <div className="flex h-screen">
          <aside className="flex w-64 flex-col border-r border-dark-700 bg-dark-800">
            <div className="flex h-16 items-center gap-2 border-b border-dark-700 px-4">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cobalt-500 font-bold text-white">
                C
              </div>
              <span className="text-lg font-bold text-white">Cobalt SOC</span>
            </div>
            <nav className="flex-1 space-y-1 px-3 py-4">
              {navigation.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                      isActive
                        ? 'bg-cobalt-500/20 text-cobalt-400'
                        : 'text-gray-400 hover:bg-dark-700 hover:text-white'
                    }`}
                  >
                    <span className="text-lg">{item.icon}</span>
                    {item.name}
                  </Link>
                );
              })}
            </nav>
            <div className="border-t border-dark-700 p-4">
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-dark-700 text-sm font-medium">
                  A
                </div>
                <div>
                  <div className="text-sm font-medium">Analyst</div>
                  <div className="text-xs text-gray-500">SOC Team</div>
                </div>
              </div>
            </div>
          </aside>
          <div className="flex flex-1 flex-col overflow-hidden">
            <header className="flex h-16 items-center justify-between border-b border-dark-700 bg-dark-800 px-6">
              <h1 className="text-lg font-semibold">
                {navigation.find((n) => n.href === pathname)?.name || 'Cobalt SOC'}
              </h1>
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2 w-2">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
                    <span className="relative inline-flex h-2 w-2 rounded-full bg-green-500" />
                  </span>
                  <span className="text-sm text-gray-400">All Systems Operational</span>
                </div>
              </div>
            </header>
            <main className="flex-1 overflow-y-auto p-6 scrollbar-thin">
              {children}
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}
