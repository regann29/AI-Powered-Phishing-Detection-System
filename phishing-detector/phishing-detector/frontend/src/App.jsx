import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "./api.js";
import AuthForm from "./components/AuthForm.jsx";
import Scanner from "./components/Scanner.jsx";
import Result from "./components/Result.jsx";
import History from "./components/History.jsx";

const SESSION_KEY = "phish-session";

function loadSession() {
  try {
    return JSON.parse(sessionStorage.getItem(SESSION_KEY)) ?? null;
  } catch {
    return null;
  }
}

export default function App() {
  const [session, setSession] = useState(loadSession);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);

  const signOut = useCallback(() => {
    sessionStorage.removeItem(SESSION_KEY);
    setSession(null);
    setResult(null);
    setHistory([]);
  }, []);

  // Any 401 means the token expired or was revoked, so return to the sign-in form.
  const guard = useCallback(
    (error) => {
      if (error instanceof ApiError && error.status === 401) signOut();
      throw error;
    },
    [signOut]
  );

  useEffect(() => {
    if (!session) return;
    api.history(session.token).then((data) => setHistory(data.items)).catch(() => signOut());
  }, [session, signOut]);

  const handleSignedIn = (data) => {
    const next = { token: data.access_token, email: data.user.email };
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(next));
    setSession(next);
  };

  const handleScan = async (run) => {
    const scan = await run(session.token).catch(guard);
    setResult(scan);
    setHistory((items) => [scan, ...items.filter((i) => i.id !== scan.id)].slice(0, 20));
  };

  const handleDelete = async (id) => {
    await api.deleteScan(session.token, id).catch(guard);
    setHistory((items) => items.filter((i) => i.id !== id));
    setResult((current) => (current?.id === id ? null : current));
  };

  return (
    <div className="page">
      <header className="masthead">
        <h1>Phishing check</h1>
        {session && (
          <div className="account">
            <span>{session.email}</span>
            <button className="link-button" onClick={signOut}>Sign out</button>
          </div>
        )}
      </header>

      {!session ? (
        <AuthForm onSignedIn={handleSignedIn} />
      ) : (
        <main>
          <Scanner onScanUrl={(url) => handleScan((t) => api.scanUrl(t, url))}
                   onScanEmail={(email) => handleScan((t) => api.scanEmail(t, email))} />
          {result && <Result result={result} />}
          <History items={history} activeId={result?.id} onSelect={setResult} onDelete={handleDelete} />
        </main>
      )}
    </div>
  );
}
