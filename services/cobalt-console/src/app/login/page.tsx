'use client';

import { useState, type FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';

export default function LoginPage() {
  const router = useRouter();
  const { login, isLoading, error } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalError(null);

    if (!username.trim() || !password.trim()) {
      setLocalError('Username and password are required');
      return;
    }

    try {
      await login(username.trim(), password);
      router.push('/');
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Login failed');
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-dark-900">
      <div className="w-full max-w-md space-y-8 p-8">
        {/* Logo / Branding */}
        <div className="text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-cobalt-500 text-2xl font-bold text-white">
            C
          </div>
          <h1 className="mt-6 text-3xl font-bold text-white">Cobalt SOC</h1>
          <p className="mt-2 text-sm text-gray-400">
            Sign in to your SOC dashboard
          </p>
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="mt-8 space-y-6">
          {(error || localError) && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
              {localError || error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label
                htmlFor="username"
                className="block text-sm font-medium text-gray-300"
              >
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={isLoading}
                className="mt-1 block w-full rounded-lg border border-dark-700 bg-dark-800 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-cobalt-500 focus:outline-none focus:ring-1 focus:ring-cobalt-500 disabled:opacity-50"
                placeholder="Enter your username"
              />
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-gray-300"
              >
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={isLoading}
                className="mt-1 block w-full rounded-lg border border-dark-700 bg-dark-800 px-4 py-3 text-sm text-white placeholder-gray-500 focus:border-cobalt-500 focus:outline-none focus:ring-1 focus:ring-cobalt-500 disabled:opacity-50"
                placeholder="Enter your password"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="flex w-full justify-center rounded-lg bg-cobalt-500 px-4 py-3 text-sm font-semibold text-white shadow-sm hover:bg-cobalt-600 focus:outline-none focus:ring-2 focus:ring-cobalt-500 focus:ring-offset-2 focus:ring-offset-dark-900 disabled:cursor-not-allowed disabled:opacity-50 transition-colors"
          >
            {isLoading ? (
              <span className="flex items-center gap-2">
                <svg
                  className="h-4 w-4 animate-spin"
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
                Signing in...
              </span>
            ) : (
              'Sign in'
            )}
          </button>
        </form>

        {/* Footer */}
        <p className="mt-4 text-center text-xs text-gray-600">
          Cobalt SOC v1.0.0 &middot; Authorized personnel only
        </p>
      </div>
    </div>
  );
}
