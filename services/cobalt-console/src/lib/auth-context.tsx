'use client';

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from 'react';

// ── Types ───────────────────────────────────────────────────────────

export interface AuthUser {
  username: string;
  role: string;
  display_name: string;
}

interface TokenPair {
  access_token: string;
  refresh_token: string;
}

interface AuthState {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => string | null;
}

// ── Token Storage ───────────────────────────────────────────────────

const ACCESS_KEY = 'cobalto_access_token';
const REFRESH_KEY = 'cobalto_refresh_token';
const USER_KEY = 'cobalto_auth_user';
const EXPIRY_KEY = 'cobalto_token_expiry';

function getStored(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function setStored(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // localStorage might be unavailable (private browsing, etc.)
  }
}

function removeStored(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch {
    // ignore
  }
}

function parseUser(stored: string | null): AuthUser | null {
  if (!stored) return null;
  try {
    return JSON.parse(stored) as AuthUser;
  } catch {
    return null;
  }
}

// ── Auth API Calls ──────────────────────────────────────────────────

const AUTH_BASE = '/api/auth';

async function loginRequest(
  username: string,
  password: string,
): Promise<{ tokens: TokenPair; user: AuthUser }> {
  const response = await fetch(`${AUTH_BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(
      data?.detail?.message || data?.message || 'Authentication failed',
    );
  }

  const data = await response.json();
  return {
    tokens: {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
    },
    user: data.user as AuthUser,
  };
}

async function refreshTokenRequest(
  refreshToken: string,
): Promise<{ tokens: TokenPair; user: AuthUser }> {
  const response = await fetch(`${AUTH_BASE}/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!response.ok) {
    throw new Error('Token refresh failed');
  }

  const data = await response.json();
  return {
    tokens: {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
    },
    user: data.user as AuthUser,
  };
}

async function logoutRequest(refreshToken: string): Promise<void> {
  try {
    await fetch(`${AUTH_BASE}/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
  } catch {
    // Best-effort — clear local state regardless
  }
}

// ── Context ─────────────────────────────────────────────────────────

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);

  // Restore session from localStorage on mount
  useEffect(() => {
    const storedUser = parseUser(getStored(USER_KEY));
    const storedAccess = getStored(ACCESS_KEY);
    const storedExpiry = getStored(EXPIRY_KEY);

    if (storedUser && storedAccess && storedExpiry) {
      const expiry = parseInt(storedExpiry, 10);
      const now = Math.floor(Date.now() / 1000);

      if (now < expiry) {
        // Token still valid
        setUser(storedUser);
        setAccessToken(storedAccess);
        setIsLoading(false);
        return;
      }

      // Token expired — try refresh
      const storedRefresh = getStored(REFRESH_KEY);
      if (storedRefresh) {
        refreshTokenRequest(storedRefresh)
          .then((result) => {
            setUser(result.user);
            setAccessToken(result.tokens.access_token);
            setStored(ACCESS_KEY, result.tokens.access_token);
            setStored(REFRESH_KEY, result.tokens.refresh_token);
            setStored(USER_KEY, JSON.stringify(result.user));
            setStored(EXPIRY_KEY, String(Math.floor(Date.now() / 1000) + 15 * 60));
          })
          .catch(() => {
            // Refresh failed — clear all
            clearSession();
          })
          .finally(() => setIsLoading(false));
        return;
      }
    }

    // No session
    clearSession();
    setIsLoading(false);
  }, []);

  const clearSession = useCallback(() => {
    setUser(null);
    setAccessToken(null);
    removeStored(ACCESS_KEY);
    removeStored(REFRESH_KEY);
    removeStored(USER_KEY);
    removeStored(EXPIRY_KEY);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    setError(null);
    setIsLoading(true);

    try {
      const result = await loginRequest(username, password);
      setUser(result.user);
      setAccessToken(result.tokens.access_token);

      // Store session
      setStored(ACCESS_KEY, result.tokens.access_token);
      setStored(REFRESH_KEY, result.tokens.refresh_token);
      setStored(USER_KEY, JSON.stringify(result.user));
      setStored(EXPIRY_KEY, String(Math.floor(Date.now() / 1000) + 15 * 60));
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Login failed';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    const refreshToken = getStored(REFRESH_KEY);
    if (refreshToken) {
      await logoutRequest(refreshToken);
    }
    clearSession();
  }, [clearSession]);

  const getAccessToken = useCallback((): string | null => {
    return accessToken;
  }, [accessToken]);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user && !!accessToken,
        isLoading,
        error,
        login,
        logout,
        getAccessToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
