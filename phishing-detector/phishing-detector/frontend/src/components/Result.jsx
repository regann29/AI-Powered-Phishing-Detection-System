const SEVERITY_LABEL = { high: "High", medium: "Medium", low: "Low" };

function RiskMeter({ score, level }) {
  return (
    <div className="meter" role="img" aria-label={`Risk score ${score} out of 100, ${level} risk`}>
      <div className="meter-track">
        <span className="zone low" />
        <span className="zone medium" />
        <span className="zone high" />
        <span className={`marker ${level}`} style={{ left: `${score}%` }} />
      </div>
      <div className="meter-scale" aria-hidden="true">
        <span style={{ left: "0%" }}>0</span>
        <span style={{ left: "35%" }}>35</span>
        <span style={{ left: "70%" }}>70</span>
        <span style={{ left: "100%" }}>100</span>
      </div>
    </div>
  );
}

export default function Result({ result }) {
  const { risk_score: score, risk_level: level, verdict, indicators, kind, preview } = result;
  const flagged = result.flagged_links ?? [];
  const terms = result.top_terms ?? [];

  return (
    <section className={`panel result ${level}`} aria-live="polite" aria-label="Result">
      <p className="subject mono">{kind === "url" ? preview : `Email: ${preview}`}</p>
      <div className="headline">
        <span className="score">{score}</span>
        <div>
          <h2>{verdict}</h2>
          <p className="muted">Risk score out of 100</p>
        </div>
      </div>
      <RiskMeter score={score} level={level} />

      <h3>Warning signs</h3>
      {indicators.length === 0 ? (
        <p className="muted">
          {kind === "url"
            ? "No warning signs in the structure of this link. That does not prove the site is safe."
            : "No rule-based warning signs were found in this message."}
        </p>
      ) : (
        <ul className="indicators">
          {indicators.map((item) => (
            <li key={item.id} className={item.severity}>
              <span className="severity">{SEVERITY_LABEL[item.severity]}</span>
              <span>{item.message}</span>
            </li>
          ))}
        </ul>
      )}

      {flagged.length > 0 && (
        <>
          <h3>Suspicious links</h3>
          <ul className="links">
            {flagged.map((link) => (
              <li key={link.host}>
                <span className="mono">{link.host}</span>
                <span className="muted">{link.reasons.join(" ")}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      {terms.length > 0 && (
        <>
          <h3>Words that raised the score</h3>
          <ul className="terms">
            {terms.map((t) => (
              <li key={t.term}>{t.term}</li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
