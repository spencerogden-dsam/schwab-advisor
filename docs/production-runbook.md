# Production OAuth Runbook (`schwab-oauth.fly.dev`)

This runbook covers promoting the `schwab-oauth` Fly app from sandbox to
production for the **AS Alerts + AS Status** prod app.

`schwab-oauth.fly.dev` is the **single OAuth broker** — it owns the prod
refresh token and exposes `/oauth/access_token?key=…` to downstream services
(`dsam-schwab-ro`, integration tests). Downstream services never hold or
refresh the refresh_token themselves, so refresh-token rotation can never
race between two refreshers.

## Prerequisites

- Fly CLI authenticated (`fly auth whoami`)
- `schwab-oauth` app already deployed (it is, as of 2026-05-06)
- Volume `schwab_data` (1GB, ord region) attached at `/data` (it is)
- Approved prod app credentials in hand:
  - Client ID: `Qxmm6orc9ZVACeK7dzmy1AESeIgsCceRRklq2rs1GAB8y4sI`
  - Client Secret: held by Spencer
- Approved Schwab user account that can complete the OAuth consent for the
  approved prod app

## 1. Deploy the latest `server.py` (with `/oauth/access_token` endpoint)

```bash
cd ~/Projects/schwab_module
fly deploy --app schwab-oauth
fly status --app schwab-oauth
```

## 2. Confirm token file path on the volume

```bash
fly ssh console --app schwab-oauth -C 'sh -c "echo $SCHWAB_TOKEN_FILE; ls -la /data"'
```

Expected: `SCHWAB_TOKEN_FILE` should resolve to a path under `/data` (e.g.
`/data/schwab_tokens.json`). If it does not, fix the secret:

```bash
fly secrets set --app schwab-oauth \
  SCHWAB_TOKEN_FILE=/data/schwab_tokens.json
```

## 3. Set production credentials as Fly secrets

> ⚠️ This swaps the broker from sandbox to production. Any sandbox tokens
> currently on the volume become unusable until you re-run the OAuth dance.

```bash
fly secrets set --app schwab-oauth \
  SCHWAB_ENVIRONMENT=production \
  SCHWAB_CLIENT_ID='Qxmm6orc9ZVACeK7dzmy1AESeIgsCceRRklq2rs1GAB8y4sI' \
  SCHWAB_CLIENT_SECRET='<paste prod secret>' \
  SCHWAB_REDIRECT_URI=https://schwab-oauth.fly.dev/oauth/callback
```

Setting secrets triggers a redeploy. Wait for `fly status` to show one
healthy machine.

## 4. Run the prod OAuth dance once

The broker will only have valid prod tokens after a human consents.

```bash
# 4a. Fetch the authorize URL from the broker
curl -s "https://schwab-oauth.fly.dev/oauth/start?key=$BROKER_API_KEY" | jq -r .authorize_url
```

`$BROKER_API_KEY` is the value of the `API_KEY` secret on `schwab-oauth`
(set when the app was first deployed; pull from 1Password or
`fly secrets list --app schwab-oauth` to confirm it's still set).

1. Open the printed authorize URL in a browser.
2. Log in with the **prod-approved** Schwab user (not the sandbox user).
3. Approve consent. Schwab will redirect to
   `https://schwab-oauth.fly.dev/oauth/callback?code=…`, which exchanges
   the code and writes tokens to `/data/schwab_tokens.json` on the volume.
4. You should see "Success! Authenticated. Token expires at …" in the
   browser.

## 5. Confirm tokens are stored

```bash
curl -s "https://schwab-oauth.fly.dev/oauth/status" | jq
# expect { authenticated: true, expired: false, expires_at: "…" }

curl -s "https://schwab-oauth.fly.dev/oauth/access_token?key=$BROKER_API_KEY" | jq
# expect { access_token: "…", expires_at: "…" }
```

## 6. Run prod integration tests

```bash
cd ~/Projects/schwab_module
SCHWAB_ALLOW_PROD_TESTS=1 \
SCHWAB_OAUTH_BROKER_KEY="$BROKER_API_KEY" \
poetry run pytest -m production -v -s
```

Expected: green test run with real prod data. Each test prints sample
records to stdout for spot-checking.

If a test reports `0 alerts` it may mean the prod-approved user has no
alerts in the date range — the test will still pass (returns an empty
list, not an error). Try widening the date filter or removing it.

## 7. Operational notes

- **Token refresh** happens lazily inside `/oauth/access_token` whenever a
  caller asks for a token whose `expires_at` is in the past. Refresh
  tokens themselves are long-lived; if they ever expire or get revoked,
  the endpoint returns 404 with `{"error": "No tokens available…"}`, and
  you re-run step 4.
- **Single source of refresh**: do **not** copy `refresh_token` out of
  `/oauth/tokens` and use it in another service. Both services would race
  on rotation. Always use `/oauth/access_token` for downstream calls.
- **Reverting to sandbox**: set `SCHWAB_ENVIRONMENT=sandbox` plus sandbox
  client_id/secret, redeploy, re-run the OAuth dance with the sandbox
  user. The token file on the volume gets overwritten.
