import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";

interface User {
  id: string;
  fullName: string;
  email: string;
  phone: string;
  referralCode: string;
  isAdmin?: boolean;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isAdmin: boolean;
  login: (token: string, user: User, isAdmin?: boolean) => void;
  adminLogin: (token: string) => void;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const savedToken = localStorage.getItem("token");
    const savedUser = localStorage.getItem("user");
    const savedAdmin = localStorage.getItem("isAdmin");
    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
      setIsAdmin(savedAdmin === "true");
    }
    setLoading(false);
  }, []);

  const login = (newToken: string, newUser: User, admin?: boolean) => {
    setToken(newToken);
    setUser(newUser);
    setIsAdmin(admin === true);
    localStorage.setItem("token", newToken);
    localStorage.setItem("user", JSON.stringify(newUser));
    localStorage.setItem("isAdmin", admin ? "true" : "false");
  };

  const adminLogin = (newToken: string) => {
    setToken(newToken);
    setUser(null);
    setIsAdmin(true);
    localStorage.setItem("token", newToken);
    localStorage.setItem("isAdmin", "true");
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    setIsAdmin(false);
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    localStorage.removeItem("isAdmin");
  };

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: !!token, isAdmin, login, adminLogin, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
