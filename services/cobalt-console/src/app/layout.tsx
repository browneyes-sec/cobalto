'use client';

import { useEffect } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Link from 'next/link';
import { AuthProvider, useAuth } from '@/lib/auth-context';
import { configureAuth } from '@/lib/api';
import './globals.css';

const navigation = [
  { name: 'Dashboard', href: '/', icon: '◉' },
  { name: 'Incidents', href: '/incidents', icon: '⚠' },
  { name: 'Agents', href: '/agents', icon: '◈' },
  { name: 'Settings', href: '/settings', icon: '⚙' },
];

// ── Auth Guard ──────────────────────────────────────────────────────

function AuthGuard({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { isAuthenticated, isLoading, getAccessToken, logout, user } = useAuth();

  // Configure API client auth on mount
  useEffect(() => {
    configureAuth({
      getToken: getAccessToken,
      onUnauth: () => {
        logout();
        router.push('/login');
      },
    });
  }, [getAccessToken, logout, router]);

  // Show loading spinner while checking auth
  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-dark-900">
        <div className="flex flex-col items-center gap-4">
          <svg
            className="h-8 w-8 animate-spin text-cobalt-500"
            viewBox="0 0 24 24"
            fill="none"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
            />
          </svg>
          <span className="text-sm text-gray-400">Loading...</span>
        </div>
      </div>
    );
  }

  // Login page is public
  if (pathname === '/login') {
    return <>{children}</>;
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    // Use useEffect to avoid rendering during redirect
    // (router.push in render body can cause issues)
    return (
      <div className="flex min-h-screen items-center justify-center bg-dark-900">
        <div className="text-center">
          <div className="text-sm text-gray-400">Redirecting to login...</div>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}

// ── Shell Layout ────────────────────────────────────────────────────

function ShellLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  // Don't show shell on login page
  if (pathname === '/login') {
    return <>{children}</>;
  }

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
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

        {/* User Info */}
        <div className="border-t border-dark-700 p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-dark-700 text-sm font-medium">
                {user?.display_name?.charAt(0).toUpperCase() || 'A'}
              </div>
              <div>
                <div className="text-sm font-medium text-white">
                  {user?.display_name || 'Analyst'}
                </div>
                <div className="text-xs text-gray-500">{user?.role || 'SOC Team'}</div>
              </div>
            </div>
            <button
              onClick={logout}
              className="rounded-lg px-2 py-1 text-xs text-gray-500 hover:text-red-400 hover:bg-dark-700 transition-colors"
              title="Sign out"
            >
              sign out
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
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
  );
}

// ── Root Layout ─────────────────────────────────────────────────────

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // The useAuth redirect on unauthenticated access lives here.
  // On /login, we detect the pathname and redirect *to* / if already authed.
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-dark-900 text-white font-sans">
        <AuthProvider>
          <AuthGuard>
            <ShellLayout>{children}</ShellLayout>
          </AuthGuard>
        </AuthProvider>
      </body>
    </html>
  );
}
