export function createTokenStorage({ storage, keyPrefix = 'ak' } = {}) {
  const store = storage || (typeof window !== 'undefined' ? window.localStorage : null);
  const tokenKey = `${keyPrefix}.token`;
  const refreshKey = `${keyPrefix}.refreshToken`;
  const read = (key) => (store ? store.getItem(key) : null);
  const write = (key, value) => {
    if (!store) return;
    if (value == null) store.removeItem(key);
    else store.setItem(key, value);
  };
  return {
    getToken: () => read(tokenKey),
    getRefreshToken: () => read(refreshKey),
    onTokens: (data) => {
      if (data.token !== undefined) write(tokenKey, data.token);
      if (data.refreshToken !== undefined) write(refreshKey, data.refreshToken);
    },
    clear: () => {
      write(tokenKey, null);
      write(refreshKey, null);
    },
  };
}

export function createAuthApi(options = {}) {
  const {
    basePath = '/api/auth',
    fetchImpl = (...args) => fetch(...args),
    getToken,
    getRefreshToken,
    onTokens,
    onUnauthorized,
  } = options;

  const remember = (data) => {
    if (data && onTokens) onTokens(data);
    return data;
  };

  async function refresh() {
    const refreshToken = getRefreshToken && getRefreshToken();
    if (!refreshToken) return null;
    try {
      const data = await request('/refresh', { method: 'POST', body: { refreshToken }, retry: false });
      return remember(data);
    } catch {
      return null;
    }
  }

  async function request(path, { method = 'GET', body, token, retry = true } = {}) {
    const headers = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    const authToken = token || (getToken && getToken());
    if (authToken) headers.authorization = `Bearer ${authToken}`;

    const res = await fetchImpl(`${basePath}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (res.status === 401 && retry && getRefreshToken && getRefreshToken()) {
      const refreshed = await refresh();
      if (refreshed) return request(path, { method, body, token: refreshed.token, retry: false });
      if (onUnauthorized) onUnauthorized();
    }

    const data = res.status === 204 ? null : await res.json().catch(() => null);
    if (!res.ok) {
      const error = new Error((data && data.error && data.error.message) || 'Request failed');
      error.code = data && data.error && data.error.code;
      error.status = res.status;
      throw error;
    }
    return data;
  }

  return {
    register: (payload) => request('/register', { method: 'POST', body: payload }).then(remember),
    login: (payload) => request('/login', { method: 'POST', body: payload }).then(remember),
    refresh,
    logout: async () => {
      const refreshToken = getRefreshToken && getRefreshToken();
      if (refreshToken) {
        await request('/logout', { method: 'POST', body: { refreshToken }, retry: false }).catch(() => {});
      }
    },
    me: () => request('/me').then((data) => data.user),
    changePassword: (payload) => request('/password/change', { method: 'POST', body: payload }),
    forgotPassword: (email) => request('/password/forgot', { method: 'POST', body: { email } }),
    resetPassword: (payload) => request('/password/reset', { method: 'POST', body: payload }),
    requestMagicLink: (email) => request('/magic-link', { method: 'POST', body: { email } }),
    verifyMagicLink: (token) =>
      request('/magic-link/verify', { method: 'POST', body: { token } }).then(remember),
    listApiKeys: () => request('/api-keys').then((data) => data.keys),
    createApiKey: (label) => request('/api-keys', { method: 'POST', body: { label } }),
    deleteApiKey: (id) => request(`/api-keys/${id}`, { method: 'DELETE' }),
    request,
  };
}
