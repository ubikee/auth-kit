import { useState } from 'react';
import { useAuth } from '../context.jsx';
import { translate } from '../i18n.js';

export function MagicLinkForm({ t, locale = 'es' }) {
  const { requestMagicLink } = useAuth();
  const tr = t || ((key, vars) => translate(locale, key, vars));
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setBusy(true);
    try {
      await requestMagicLink(email);
      setSent(true);
    } finally {
      setBusy(false);
    }
  }

  if (sent) return <p className="ak-note">{tr('auth.checkEmail')}</p>;

  return (
    <div className="ak-magic">
      <label className="ak-field">
        <span>{tr('auth.email')}</span>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required />
      </label>
      <button className="ak-button ak-button--ghost" type="button" disabled={busy} onClick={handleSubmit}>
        {busy ? tr('auth.working') : tr('auth.magicLink')}
      </button>
    </div>
  );
}
