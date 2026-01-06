import React, { createContext, useContext, useState, useEffect } from 'react';
import { getUserData, isAuthenticated, clearSession } from '@/utils/sessionUtils';

interface AuthContextType {
  user: { name: string; email: string } | null;
  isAuthenticated: boolean;
  signOut: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<{ name: string; email: string } | null>(null);
  const [isAuth, setIsAuth] = useState(false);

  useEffect(() => {
    const checkAuth = () => {
      const authStatus = isAuthenticated();
      setIsAuth(authStatus);
      if (authStatus) {
        setUser(getUserData());
      } else {
        setUser(null);
      }
    };

    checkAuth();
    // Check auth status every minute
    const interval = setInterval(checkAuth, 60000);
    return () => clearInterval(interval);
  }, []);

  const signOut = () => {
    clearSession();
    setUser(null);
    setIsAuth(false);
  };

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: isAuth, signOut }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}; 