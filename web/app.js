const token = document.querySelector("#token");
const sql = document.querySelector("#sql");
const decision = document.querySelector("#decision");
const budget = document.querySelector("#budget");
const latency = document.querySelector("#latency");
const reasons = document.querySelector("#reasons");
const details = document.querySelector("#details");
const results = document.querySelector("#results");

async function request(path) {
  decision.textContent = "RUNNING";
  results.replaceChildren();
  const response = await fetch(path, {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-API-Key": token.value},
    body: JSON.stringify({sql: sql.value})
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
  decision.textContent = payload.decision;
  decision.dataset.state = payload.decision.toLowerCase();
  latency.textContent = payload.elapsed_ms === undefined ? "not executed" : `${payload.elapsed_ms} ms`;
  budget.textContent = payload.privacy ? `${payload.privacy.budget_remaining} ε left` : "unchanged";
  reasons.replaceChildren(...payload.reason_codes.map(code => {
    const chip = document.createElement("span"); chip.textContent = code; return chip;
  }));
  if (payload.rows?.length) renderTable(payload.columns, payload.rows);
  details.textContent = JSON.stringify(payload.canonical_plan || {
    rewritten_sql: payload.canonical_query,
    privacy: payload.privacy,
    audit_entry_id: payload.audit_entry_id
  }, null, 2);
}

function renderTable(columns, rows) {
  const head = document.createElement("tr");
  for (const name of columns) { const th = document.createElement("th"); th.textContent = name; head.append(th); }
  results.append(head);
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const name of columns) { const td = document.createElement("td"); td.textContent = row[name] ?? "—"; tr.append(td); }
    results.append(tr);
  }
}

async function guarded(path) {
  try { await request(path); }
  catch (error) { decision.textContent = "ERROR"; details.textContent = String(error); }
}

document.querySelector("#run").addEventListener("click", () => guarded("/v1/query"));
document.querySelector("#explain").addEventListener("click", () => guarded("/v1/policy/explain"));
