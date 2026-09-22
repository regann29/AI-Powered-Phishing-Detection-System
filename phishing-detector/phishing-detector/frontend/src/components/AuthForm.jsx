import { useState } from "react";
import { api } from "../api.js";

export default function AuthForm({ onSignedIn }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const isRegister = mode === "register";

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (isRegister) await api.register(email, password);
      onSignedIn(await api.login(email, password));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel auth" aria-labelledby="auth-title">
      <h2 id="auth-title">{isRegister ? "Create an account" : "Sign in"}</h2>
      <p className="muted">
        Check a link or an email for signs of phishing. Your results stay private to your account.
      </p>
      <form onSubmit={submit}>
        <label>
          Email
          <input type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label>
          Password
          <input
            type="password"
            autoComplete={isRegister ? "new-password" : "current-password"}
            required
            minLength={isRegister ? 10 : undefined}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {isRegister && <span className="hint">At least 10 characters, with a letter and a digit.</span>}
        </label>
        {error && <p className="error" role="alert">{error}</p>}
        <div className="actions">
          <button className="primary" disabled={busy}>
            {busy ? "Please wait" : isRegister ? "Create account" : "Sign in"}
          </button>
          <button type="button" className="link-button" onClick={() => { setMode(isRegister ? "login" : "register"); setError(""); }}>
            {isRegister ? "I already have an account" : "Create an account"}
          </button>
        </div>
      </form>
    </section>
  );
}
