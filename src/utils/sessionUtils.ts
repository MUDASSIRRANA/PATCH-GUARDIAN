interface User {
  name: string;
  email: string;
}

interface Session {
  user: User;
  token: string;
  expiresAt: string;
}

export const setSession = (session: Session): void => {
  localStorage.setItem('session', JSON.stringify(session));
};

export const getSession = (): Session | null => {
  const sessionStr = localStorage.getItem('session');
  if (!sessionStr) return null;

  try {
    const session = JSON.parse(sessionStr);
    if (new Date(session.expiresAt) < new Date()) {
      clearSession();
      return null;
    }
    return session;
  } catch {
    return null;
  }
};

export const clearSession = (): void => {
  localStorage.removeItem('session');
};

export const isAuthenticated = (): boolean => {
  return !!getSession();
};

export const getAuthToken = (): string | null => {
  const session = getSession();
  return session?.token || null;
};

export const getUserData = (): { name: string; email: string } | null => {
  const session = getSession();
  return session?.user || null;
}; 