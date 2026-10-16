import { useState } from 'react';
import { useAuth } from '../context.jsx';
import { translate } from '../i18n.js';

export function RegisterForm({ t, locale = 'es', onSuccess, requireName = true }) {
  const { register, error } = useAuth();
  const tr = t || ((key, vars) => translate(locale, key, vars));
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setBusy(true);
    try {
      const user = await register(requireName ? { name, email, password } : { email, password });
      if (onSuccess) onSuccess(user);
    } catch {
      /* el error queda expuesto por el contexto */
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="ak-form" onSubmit={handleSubmit}>
      {requireName && (
        <label className="ak-field">
          <span>{tr('auth.name')}</span>
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" required />
        </label>
      )}
      <label className="ak-field">
        <span>{tr('auth.email')}</span>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required />
      </label>
      <label className="ak-field">
        <span>{tr('auth.password')}</span>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          required
        />
      </label>
      {error && (
        <p className="ak-error" role="alert">
          {error.message || tr('auth.error')}
        </p>
      )}
      <button className="ak-button" type="submit" disabled={busy}>
        {busy ? tr('auth.working') : tr('auth.register')}
      </button>
    </form>
  );
}
