export const DICT = {
  es: {
    'auth.email': 'Correo electrónico',
    'auth.password': 'Contraseña',
    'auth.currentPassword': 'Contraseña actual',
    'auth.newPassword': 'Nueva contraseña',
    'auth.name': 'Nombre',
    'auth.login': 'Entrar',
    'auth.register': 'Crear cuenta',
    'auth.logout': 'Salir',
    'auth.magicLink': 'Enviar enlace de acceso',
    'auth.forgotPassword': '¿Olvidaste tu contraseña?',
    'auth.resetPassword': 'Restablecer contraseña',
    'auth.working': 'Un momento…',
    'auth.loading': 'Cargando…',
    'auth.checkEmail': 'Revisa tu correo para continuar.',
    'auth.welcome': 'Hola, {name}',
    'auth.error': 'No se pudo completar la operación.',
  },
  en: {
    'auth.email': 'Email',
    'auth.password': 'Password',
    'auth.currentPassword': 'Current password',
    'auth.newPassword': 'New password',
    'auth.name': 'Name',
    'auth.login': 'Sign in',
    'auth.register': 'Create account',
    'auth.logout': 'Sign out',
    'auth.magicLink': 'Send sign-in link',
    'auth.forgotPassword': 'Forgot your password?',
    'auth.resetPassword': 'Reset password',
    'auth.working': 'One moment…',
    'auth.loading': 'Loading…',
    'auth.checkEmail': 'Check your email to continue.',
    'auth.welcome': 'Hi, {name}',
    'auth.error': 'The operation could not be completed.',
  },
};

export function translate(locale, key, vars) {
  const table = DICT[locale] || DICT.es;
  let text = table[key] != null ? table[key] : (DICT.es[key] != null ? DICT.es[key] : key);
  if (vars) {
    for (const [name, value] of Object.entries(vars)) {
      text = text.replace(new RegExp(`\\{${name}\\}`, 'g'), value);
    }
  }
  return text;
}
