import { useState } from "react";

import { useAuth } from "../context/useAuth";

export default function AuthScreen() {
  const { login, register } = useAuth();
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        await register(email, password);
      }
    } catch (requestError) {
      setError(
        requestError.message ||
          "Something went wrong. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app auth-screen">
      <div className="panel auth-panel">
        <h1 className="auth-title">EVIDENCE</h1>
        <p className="auth-subtitle">
          Cybersecurity Evidence Investigator
        </p>

        <div className="auth-tabs">
          <button
            type="button"
            className={
              mode === "login"
                ? "auth-tab active"
                : "auth-tab"
            }
            onClick={() => {
              setMode("login");
              setError("");
            }}
          >
            Sign in
          </button>
          <button
            type="button"
            className={
              mode === "register"
                ? "auth-tab active"
                : "auth-tab"
            }
            onClick={() => {
              setMode("register");
              setError("");
            }}
          >
            Create account
          </button>
        </div>

        <form
          className="auth-form"
          onSubmit={submit}
        >
          <label className="auth-label">
            Email
            <input
              type="email"
              className="auth-input"
              value={email}
              autoComplete="email"
              required
              onChange={(event) =>
                setEmail(event.target.value)
              }
            />
          </label>

          <label className="auth-label">
            Password
            <input
              type="password"
              className="auth-input"
              value={password}
              minLength={
                mode === "register" ? 8 : undefined
              }
              maxLength={72}
              autoComplete={
                mode === "login"
                  ? "current-password"
                  : "new-password"
              }
              required
              onChange={(event) =>
                setPassword(event.target.value)
              }
            />
          </label>

          {mode === "register" && (
            <p className="auth-hint">
              At least 8 characters.
            </p>
          )}

          {error && (
            <p className="auth-error">{error}</p>
          )}

          <button
            type="submit"
            className="auth-submit"
            disabled={loading}
          >
            {loading
              ? "Please wait..."
              : mode === "login"
                ? "Sign in"
                : "Create account"}
          </button>
        </form>
      </div>
    </div>
  );
}
