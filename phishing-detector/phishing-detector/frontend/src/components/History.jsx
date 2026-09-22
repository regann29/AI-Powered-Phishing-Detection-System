const time = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

export default function History({ items, activeId, onSelect, onDelete }) {
  return (
    <section className="panel" aria-labelledby="history-title">
      <h2 id="history-title">Recent checks</h2>
      {items.length === 0 ? (
        <p className="muted">Nothing checked yet. Paste a link or an email above to start.</p>
      ) : (
        <ul className="history">
          {items.map((item) => (
            <li key={item.id} className={item.id === activeId ? "active" : undefined}>
              <button className="history-open" onClick={() => onSelect(item)}>
                <span className={`pill ${item.risk_level}`}>{item.risk_score}</span>
                <span className="history-text">
                  <span className="mono truncate">{item.preview}</span>
                  <span className="meta muted">
                    <span>{item.kind === "url" ? "Link" : "Email"}: {item.verdict}</span>
                    <span>{time.format(new Date(item.created_at))}</span>
                  </span>
                </span>
              </button>
              <button className="link-button" onClick={() => onDelete(item.id)} aria-label={`Delete check of ${item.preview}`}>
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
