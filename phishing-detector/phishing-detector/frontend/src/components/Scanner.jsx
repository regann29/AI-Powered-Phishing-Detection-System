import { useState } from "react";

const EMPTY_EMAIL = { sender: "", reply_to: "", subject: "", body: "" };

export default function Scanner({ onScanUrl, onScanEmail }) {
  const [tab, setTab] = useState("url");
  const [url, setUrl] = useState("");
  const [email, setEmail] = useState(EMPTY_EMAIL);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const setField = (name) => (e) => setEmail((current) => ({ ...current, [name]: e.target.value }));

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (tab === "url") await onScanUrl(url.trim());
      else await onScanEmail(email);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const switchTab = (next) => { setTab(next); setError(""); };

  return (
    <section className="panel" aria-label="Scanner">
      <div className="tabs" role="tablist" aria-label="What do you want to check?">
        {[["url", "Link"], ["email", "Email"]].map(([id, label]) => (
          <button key={id} role="tab" id={`tab-${id}`} aria-selected={tab === id} aria-controls="scan-panel"
                  className={tab === id ? "tab active" : "tab"} onClick={() => switchTab(id)}>
            {label}
          </button>
        ))}
      </div>

      <form id="scan-panel" role="tabpanel" aria-labelledby={`tab-${tab}`} onSubmit={submit}>
        {tab === "url" ? (
          <label>
            Web address
            <input className="mono" type="text" inputMode="url" spellCheck="false" autoComplete="off" required
                   placeholder="https://example.com/account/verify" value={url} onChange={(e) => setUrl(e.target.value)} />
            <span className="hint">The link is analysed as text. It is never opened.</span>
          </label>
        ) : (
          <>
            <div className="row">
              <label>
                From
                <input type="email" spellCheck="false" placeholder="sender@example.com" value={email.sender} onChange={setField("sender")} />
              </label>
              <label>
                Reply-to
                <input type="email" spellCheck="false" placeholder="Only if different" value={email.reply_to} onChange={setField("reply_to")} />
              </label>
            </div>
            <label>
              Subject
              <input type="text" maxLength={300} value={email.subject} onChange={setField("subject")} />
            </label>
            <label>
              Message
              <textarea rows={9} required maxLength={50000} value={email.body} onChange={setField("body")}
                        placeholder="Paste the message text. HTML source works too, and lets us compare link text with where links really go." />
              <span className="hint">The message itself is not stored. Only the result is saved.</span>
            </label>
          </>
        )}
        {error && <p className="error" role="alert">{error}</p>}
        <div className="actions">
          <button className="primary" disabled={busy}>{busy ? "Checking" : `Check ${tab === "url" ? "link" : "email"}`}</button>
        </div>
      </form>
    </section>
  );
}
