import { useEffect } from 'react';
import { useAuth } from '../context.jsx';
import { translate } from '../i18n.js';

export function ProtectedRoute({ children, roles, fallback = null, onUnauthenticated, t, locale = 'es' }) {
  const { user, loading } = useAuth();
  const tr = t || ((key, vars) => translate(locale, key, vars));
  const unauthorized = !loading && (!user || (roles && roles.length && !roles.includes(user.role)));

  useEffect(() => {
    if (unauthorized && onUnauthenticated) onUnauthenticated(user);
  }, [unauthorized, onUnauthenticated, user]);

  if (loading) return fallback ?? <div className="ak-loading">{tr('auth.loading')}</div>;
  if (unauthorized) return null;
  return children;
}
