import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

const AuthContext = createContext(null);

export function AuthProvider({ api, children, onLogin, onLogout }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .me()
      .then((current) => {
        if (active) setUser(current);
      })
      .catch(() => {})
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [api]);

  const adopt = useCallback(
    (data) => {
      setUser(data.user);
      setError(null);
      if (onLogin) onLogin(data.user);
      return data.user;
    },
    [onLogin]
  );

  const value = useMemo(
    () => ({
      user,
      loading,
      error,
      isAuthenticated: Boolean(user),
      login: async (credentials) => {
        try {
          return adopt(await api.login(credentials));
        } catch (err) {
          setError(err);
          throw err;
        }
      },
      register: async (payload) => {
        try {
          return adopt(await api.register(payload));
        } catch (err) {
          setError(err);
          throw err;
        }
      },
      verifyMagicLink: async (token) => adopt(await api.verifyMagicLink(token)),
      requestMagicLink: (email) => api.requestMagicLink(email),
      forgotPassword: (email) => api.forgotPassword(email),
      resetPassword: (payload) => api.resetPassword(payload),
      logout: async () => {
        await api.logout();
        setUser(null);
        if (onLogout) onLogout();
      },
      refresh: async () => {
        const current = await api.me();
        setUser(current);
        return current;
      },
      setUser,
      clearError: () => setError(null),
    }),
    [api, user, loading, error, adopt, onLogin, onLogout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth debe usarse dentro de <AuthProvider>');
  return ctx;
}
