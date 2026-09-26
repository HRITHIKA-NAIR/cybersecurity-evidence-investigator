import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  loginUser,
  registerUser,
  setAuthToken,
} from "../services/api";
import { AuthContext } from "./authContextObject";

const STORAGE_KEY = "evidence_auth";

function readStoredAuth() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed?.token || !parsed?.user) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(() => {
    const stored = readStoredAuth();
    if (stored) setAuthToken(stored.token);
    return stored;
  });

  useEffect(() => {
    setAuthToken(auth?.token || null);

    if (auth) {
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(auth)
      );
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  }, [auth]);

  const login = async (email, password) => {
    const data = await loginUser(email, password);
    setAuth(data);
    return data;
  };

  const register = async (email, password) => {
    const data = await registerUser(email, password);
    setAuth(data);
    return data;
  };

  const logout = () => {
    setAuth(null);
  };

  const value = useMemo(
    () => ({
      user: auth?.user || null,
      isAuthenticated: Boolean(auth?.token),
      login,
      register,
      logout,
    }),
    [auth]
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
