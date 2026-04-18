// ============================================================
// Schwab Developer Portal — bulk OpenAPI spec downloader
// ============================================================
// Paste this into Chrome DevTools console while logged in at
// https://developer.schwab.com (any page). It will:
//   1. Reuse the browser's Akamai session cookies (no manual auth)
//   2. GET /api-specification/<name> for each AS product
//   3. Trigger a browser download of each spec as
//      schwab-<slug>-openapi.json
//
// If a product returns 403/404, it's skipped silently.
//
// Move the downloaded files to docs/ after the run.
// ============================================================

(async () => {
  // Grab the Bearer token from the current session. The SPA may store it
  // in localStorage or sessionStorage under various keys.
  let token = null;
  const scanStore = (store) => {
    for (let i = 0; i < store.length; i++) {
      const v = store.getItem(store.key(i));
      if (!v) continue;
      // Direct match
      if (/^I0\.[A-Za-z0-9_.-]+@?$/.test(v)) return v;
      if (/^Bearer I0\./.test(v)) return v;
      // JSON-wrapped
      if (v.includes("I0.") && (v[0] === "{" || v[0] === "[")) {
        try {
          const parsed = JSON.parse(v);
          const stack = [parsed];
          while (stack.length) {
            const node = stack.pop();
            if (typeof node === "string" && /^I0\.[A-Za-z0-9_.-]+@?$/.test(node)) {
              return node;
            }
            if (node && typeof node === "object") {
              for (const val of Object.values(node)) stack.push(val);
            }
          }
        } catch {}
      }
    }
    return null;
  };
  token = scanStore(localStorage) || scanStore(sessionStorage);
  if (!token) {
    // Fallback: ask user to paste it
    token = prompt(
      "Could not auto-detect the Bearer token.\n" +
      "Open DevTools > Network, click any /api-specification/... request, " +
      "copy the Authorization header value (starts with 'Bearer I0...'), " +
      "and paste it here:"
    );
    if (!token) return console.error("No token provided — aborting.");
  }
  if (!token.startsWith("Bearer ")) token = "Bearer " + token;
  console.log("Using token prefix:", token.slice(0, 30) + "...");

  const BASE =
    "https://jfk2-api-gateway.schwab.com/api/DevPortalV3.DevPortalExperienceApi" +
    "/v1/DevPortalExperience/api/v1";

  const headers = () => ({
    "Authorization": token,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Schwab-Client-CorrelId": crypto.randomUUID(),
    "Schwab-Resource-Version": "1",
    "Schwab-Gateway-Scope": "update",
    "Schwab-Client-AppId": "AD00007720",
    "Schwab-Client-Channel": "GW",
    "Schwab-Client-Env": "PROD",
  });

  // Candidate AS product names — edit as needed.
  const candidates = [
    "AS Account",
    "AS Account Blocks",
    "AS Account Inquiry",
    "AS Account Preferences and Authorizations",
    "AS Account Synchronization",
    "AS Address Change",
    "AS Alerts",
    "AS Balances",
    "AS Client Inquiry",
    "AS Cost Basis",
    "AS Daily Data",
    "AS Digital Account Open",
    "AS Document Preferences",
    "AS Feature Enrollment",
    "AS iRebal",
    "AS Man Fee File Upload",
    "AS Move Money",
    "AS Move Money Activity",
    "AS Positions",
    "AS Profiles",
    "AS Reports",
    "AS Service Request",
    "AS Standing Authorizations",
    "AS Status",
    "AS Trading",
    "AS Trading File Upload",
    "AS Transactions",
    "AS User Authorization",
  ];

  const slug = (name) =>
    name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

  const hits = [];
  for (const name of candidates) {
    const url = `${BASE}/api-specification/${encodeURIComponent(name)}`;
    try {
      const resp = await fetch(url, { headers: headers() });
      if (!resp.ok) {
        console.log(`  ${resp.status}  ${name}`);
        continue;
      }
      const wrapped = await resp.json();
      // The "specification" field is a JSON string. Unwrap it.
      const specRaw = wrapped.specification;
      if (!specRaw) {
        console.log(`  200 but no 'specification' field  ${name}`);
        continue;
      }
      const spec = typeof specRaw === "string" ? JSON.parse(specRaw) : specRaw;
      const json = JSON.stringify(spec, null, 2);
      const filename = `schwab-${slug(name)}-openapi.json`;

      // Trigger download
      const blob = new Blob([json], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(a.href);

      hits.push({ name, filename, bytes: json.length });
      console.log(`  OK   ${name} -> ${filename} (${json.length} bytes)`);

      // Be polite — avoid hammering the gateway
      await new Promise((r) => setTimeout(r, 400));
    } catch (e) {
      console.log(`  ERR  ${name}: ${e.message}`);
    }
  }

  console.log(`\nDone. ${hits.length} specs downloaded:`);
  for (const h of hits) console.log(`  ${h.name}  -> ${h.filename}  (${h.bytes} bytes)`);
  console.log(
    "\nMove the downloaded .json files into " +
    "/Users/spencerogden/Projects/schwab_module_alerts/docs/"
  );
})();
