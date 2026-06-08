[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/robcerda-monarch-mcp-server-badge.png)](https://mseep.ai/app/robcerda-monarch-mcp-server)

# Monarch Money MCP Server

A Model Context Protocol (MCP) server for integrating with the Monarch Money personal finance platform. This server provides seamless access to your financial accounts, transactions, budgets, and analytics through Claude Desktop and Claude Code.

My MonarchMoney referral: https://www.monarchmoney.com/referral/ufmn0r83yf?r_source=share

**Built with the [MonarchMoneyCommunity Python library](https://github.com/bradleyseanf/monarchmoneycommunity)** - An actively maintained community fork of the Monarch Money API with full MFA support.

<a href="https://glama.ai/mcp/servers/@robcerda/monarch-mcp-server">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@robcerda/monarch-mcp-server/badge" alt="monarch-mcp-server MCP server" />
</a>

## 🚀 Quick Start

### 1. Installation

1. **Clone this repository**:
   ```bash
   git clone https://github.com/robcerda/monarch-mcp-server.git
   cd monarch-mcp-server
   ```

2. **Install dependencies**:

   **Using `pip`**:
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

   **Using `uv`** (alternative):
   ```bash
   uv sync
   ```

3. **Configure Claude Desktop**:
   Add this to your Claude Desktop configuration file:

   **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

   **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

   ```json
   {
     "mcpServers": {
       "Monarch Money": {
         "command": "/opt/homebrew/bin/uv",
         "args": [
           "run",
           "--with",
           "mcp[cli]",
           "--with-editable",
           "/path/to/your/monarch-mcp-server",
           "mcp",
           "run",
           "/path/to/your/monarch-mcp-server/src/monarch_mcp_server/server.py"
         ]
       }
     }
   }
   ```

   **Important**: Replace `/path/to/your/monarch-mcp-server` with your actual path!

4. **Restart Claude Desktop**

**OR**

3. **Configure Claude Code** (CLI):
   Add this to your Claude Code configuration file:

   **Global** (all projects):

   **macOS/Linux**: `~/.claude.json`

   **Windows**: `%USERPROFILE%\.claude.json`

   ```json
   {
     "mcpServers": {
       "Monarch Money": {
         "command": "/opt/homebrew/bin/uv",
         "args": [
           "run",
           "--with",
           "mcp[cli]",
           "--with-editable",
           "/path/to/your/monarch-mcp-server",
           "mcp",
           "run",
           "/path/to/your/monarch-mcp-server/src/monarch_mcp_server/server.py"
         ]
       }
     }
   }
   ```

   **Project-level** (specific directory):

   Create `.mcp.json` in your project directory:

   ```json
   {
     "Monarch Money": {
       "command": "/opt/homebrew/bin/uv",
       "args": [
         "run",
         "--with",
         "mcp[cli]",
         "--with-editable",
         "/path/to/your/monarch-mcp-server",
         "mcp",
         "run",
         "/path/to/your/monarch-mcp-server/src/monarch_mcp_server/server.py"
       ]
     }
   }
   ```

   **If installed via `pip`** instead of `uv`, use:
   ```json
   {
     "command": "python",
     "args": ["/path/to/your/monarch-mcp-server/src/monarch_mcp_server/server.py"]
   }
   ```

   **Important**: Replace `/path/to/your/monarch-mcp-server` with your actual path!

4. **Restart Claude Code**

### 2. One-Time Authentication Setup

**Important**: For security and MFA support, authentication is done outside of Claude.

#### Option A: Email/Password Login

Open Terminal and run:

**Using `python`**:
```bash
cd /path/to/your/monarch-mcp-server
python login_setup.py
```

**Using `uv`**:
```bash
cd /path/to/your/monarch-mcp-server
uv run python login_setup.py
```

Follow the prompts:
- Enter your Monarch Money email and password
- Provide 2FA code if you have MFA enabled
- Session will be saved automatically

### 3. Start Using

Once authenticated, use these tools directly in Claude Desktop or Claude Code:
- `get_accounts` - View all your financial accounts
- `get_transactions` - Recent transactions with filtering
- `get_budgets` - Budget information and spending
- `get_cashflow` - Income/expense analysis

## 🌐 Remote Deployment (OAuth-protected HTTP)

The server also runs as a **remote, public HTTPS MCP service** you can add to the
Claude app (iOS/Android/web) as a custom connector. In this mode it speaks the
**Streamable HTTP** transport and acts as an **OAuth 2.0 Resource Server**: it
validates bearer JWTs issued by *your* Identity Provider (Auth0 or Zitadel) and
never hosts the login flow itself. Claude logs the user in against the IdP.

```
Claude app ──(OAuth login)──▶ Your IdP (Auth0 / Zitadel)
    │                              │ issues JWT (aud = this server)
    └──(MCP + Bearer JWT)──▶ Reverse proxy (TLS) ──▶ monarch-mcp container (HTTP)
                                                         └─ validates iss/aud/exp/sig
                                                         └─ calls Monarch with a
                                                            headless session
```

TLS terminates at **your** ingress/reverse proxy; the container serves plain
HTTP on `$PORT`. The public URL is HTTPS.

### Architecture / transports

| `TRANSPORT` | Use | Auth |
|-------------|-----|------|
| `stdio` (code default) | Claude Desktop/Code, `mcp run` | none (local) |
| `http` (container default) | Remote custom connector | OAuth 2.0 bearer JWT |

Key endpoints (HTTP mode):

- `POST /mcp` — the MCP Streamable HTTP endpoint (requires `Bearer` token).
- `GET /.well-known/oauth-protected-resource` — RFC 9728 Protected Resource
  Metadata, advertising your IdP as the authorization server and this server's
  own resource id.
- `GET /healthz` — unauthenticated liveness probe.

On every MCP request the server requires a `Bearer` token and validates: the JWT
signature against the IdP JWKS (fetched + cached from `OAUTH_JWKS_URI`),
`iss == OAUTH_ISSUER`, `aud == OAUTH_AUDIENCE` (this server's resource id), and
`exp`/`nbf`. On failure it returns `401` with a `WWW-Authenticate` header
pointing at the resource metadata, so Claude knows where to authenticate.

### 1. Deploy with Docker Compose

```bash
cp .env.example .env       # then edit — see variables below
docker compose up -d --build
curl -fsS http://127.0.0.1:8000/healthz   # -> {"status":"ok"}
```

Front the container with your existing reverse proxy (Caddy/Nginx/Traefik),
terminating TLS and proxying `https://monarch-mcp.example.com` → the container's
`:8000`. Set `PUBLIC_URL`/`OAUTH_AUDIENCE` to that HTTPS URL.

The named `monarch-session` volume persists the Monarch session token across
restarts. Headless login (below) populates it on first use.

### 2. Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `TRANSPORT` | `stdio` (code) / `http` (container) | `stdio` or `http` |
| `PORT` | `8000` | HTTP port (plain HTTP behind your proxy) |
| `HOST` | `0.0.0.0` | Bind address |
| `RATE_LIMIT_PER_MINUTE` | `120` | Per-IP request budget (`0` disables); `/healthz` exempt |
| `MONARCH_EMAIL` / `MONARCH_PASSWORD` | — | Headless Monarch login |
| `MONARCH_MFA_SECRET` | — | Base32 TOTP secret for non-interactive MFA |
| `SESSION_STORE_PATH` | `/data/monarch-session` | Persisted session token path (mounted volume) |
| `OAUTH_ISSUER` | — | Token `iss` (exact, trailing slash matters) |
| `OAUTH_AUDIENCE` | `PUBLIC_URL` | **This server's resource id** = required token `aud` |
| `OAUTH_JWKS_URI` | — | IdP JWKS endpoint for signature verification |
| `REQUIRED_READ_SCOPE` | `monarch:read` | Scope required on every request |
| `REQUIRED_WRITE_SCOPE` | `monarch:write` | Scope required for mutating tools |
| `READ_ONLY` | `true` | When true, mutating tools are not registered |
| `PUBLIC_URL` | — | Public HTTPS URL (RFC 9728 metadata) |

> **Leaving `OAUTH_*` blank runs the server unauthenticated** (a warning is
> logged). Only do that for local/stdio development — never expose it publicly.

### 3. Headless Monarch login

In a container there is no browser, so the server logs in non-interactively:

1. On the first tool call it tries the persisted session at `SESSION_STORE_PATH`.
2. If absent/expired, it logs in with `MONARCH_EMAIL` / `MONARCH_PASSWORD`,
   completing MFA automatically using a TOTP code derived from
   `MONARCH_MFA_SECRET` (via `pyotp`).
3. The resulting session token is persisted and reused across cold starts;
   expiry triggers an automatic re-login.

To obtain `MONARCH_MFA_SECRET`: in Monarch, set up an **authenticator app** for
two-factor auth and use the **manual entry / setup key** (a Base32 string) shown
next to the QR code. Startup never blocks on auth — if Monarch auth is
unavailable, individual tool calls return a clear error instead.

### 4. Identity Provider setup

You define **one API/resource** (its identifier becomes `OAUTH_AUDIENCE`) and
**two scopes**: `monarch:read` and `monarch:write`. Audience mismatch is the #1
failure mode — the `aud` in issued tokens must **exactly** equal `OAUTH_AUDIENCE`.

#### Auth0

1. **APIs → Create API**
   - *Identifier (audience)*: `https://monarch-mcp.example.com` — set this as
     `OAUTH_AUDIENCE`.
   - Signing algorithm: **RS256**.
   - Enable **RBAC** and **Add Permissions in the Access Token**.
2. **Permissions** tab on the API: add `monarch:read` and `monarch:write`.
3. Discover the rest from the tenant:
   - `OAUTH_ISSUER`  = `https://YOUR_TENANT.us.auth0.com/` (note trailing slash).
   - `OAUTH_JWKS_URI` = `https://YOUR_TENANT.us.auth0.com/.well-known/jwks.json`.
4. **Dynamic Client Registration**: Auth0 supports DCR but it is **off by
   default**. Either enable it (`PATCH /api/v2/tenants/settings` with
   `enabled_clients`/`flags.enable_dynamic_client_registration`), or create a
   **Regular Web Application**, grant it the two scopes, and paste its
   **Client ID/Secret** into Claude's connector *Advanced settings* (see §5).

#### Zitadel

1. **Create a Project**; inside it **Create an API application** (auth method
   *JWT (Private Key)* or *Basic* — only the resource matters for the RS).
2. The API's resource identifier / audience is typically the **Project ID** or a
   configured URN. Set `OAUTH_AUDIENCE` to the value Zitadel places in the
   token's `aud` (verify with a test token). Add an **Audience** action/claim if
   you need it to equal `https://monarch-mcp.example.com`.
3. **Roles**: add project roles `monarch:read` and `monarch:write`; map them into
   the token as scopes/claims (Zitadel can emit them in `scope`).
4. Discovery:
   - `OAUTH_ISSUER`  = `https://your-instance.zitadel.cloud` (your instance URL).
   - `OAUTH_JWKS_URI` = `https://your-instance.zitadel.cloud/oauth/v2/keys`.
5. **DCR**: Zitadel exposes OIDC discovery; if the connector cannot self-register,
   create an application and paste its Client ID/Secret into Claude (see §5).

> **Verifying the audience**: decode a test access token (jwt.io) and confirm
> `aud` exactly equals `OAUTH_AUDIENCE`. A trailing-slash difference vs. the
> advertised resource id is tolerated by the verifier; a different value is not.

### 5. Add to Claude as a custom connector

1. In the Claude app: **Settings → Connectors → Add custom connector**.
2. **URL**: `https://monarch-mcp.example.com/mcp`.
3. Claude fetches `/.well-known/oauth-protected-resource`, discovers your IdP,
   and starts the OAuth login. If your IdP supports **Dynamic Client
   Registration**, no client setup is needed. Otherwise open **Advanced
   settings** and paste the **OAuth Client ID** (and **Client Secret** if your
   IdP requires one) you created above.
4. Log in at your IdP, consenting to `monarch:read` (and `monarch:write` if you
   run with `READ_ONLY=false`).

### 6. Kubernetes notes

The Compose service maps to:

- **Deployment** (1 replica — rate limiting is per-process/in-memory; for
  multiple replicas enforce limits at the Ingress instead).
- **PersistentVolumeClaim** (`ReadWriteOnce`) mounted at `/data`, with
  `SESSION_STORE_PATH=/data/monarch-session`.
- **Secret** (Monarch creds, OAuth config) + optional **ConfigMap** (non-secret
  config), referenced via `envFrom`.
- **Service** (ClusterIP) + **Ingress** for TLS, with readiness/liveness probes
  on `GET /healthz`.

### Security notes

- **Read-only by default** (`READ_ONLY=true`): mutating tools are not registered
  at all. Set `READ_ONLY=false` to enable them; they then additionally require
  the `monarch:write` scope in the caller's token.
- Tokens, credentials, and full financial payloads are **never logged**.
- Basic per-IP rate limiting protects a single instance (`RATE_LIMIT_PER_MINUTE`).
- The container runs as a **non-root** user.
- Asymmetric JWT algorithms only (RS/ES); `none`/HMAC are rejected.

### Design tradeoffs (SDK vs. MCP auth spec)

- The installed MCP SDK (`mcp` 1.27.x) already implements the Resource Server
  pieces of the 2025-06-18 auth spec: a `TokenVerifier` hook, RFC 9728 metadata,
  bearer middleware, and `401 + WWW-Authenticate`. We supply only the JWT
  verifier (`oauth.py`) and let the SDK wire the rest — no custom ASGI auth
  middleware was needed.
- The SDK's `required_scopes` is enforced **globally** per request, not per
  tool. So we require `monarch:read` globally and check `monarch:write`
  **inside** each mutating tool using the SDK's authenticated-token contextvar.

## ✨ Features

### 📊 Account Management
- **Get Accounts**: View all linked financial accounts with balances and institution info
- **Get Account Holdings**: See securities and investments in investment accounts
- **Refresh Accounts**: Request real-time data updates from financial institutions

### 💰 Transaction Access
- **Get Transactions**: Fetch transaction data with filtering by date, account, and pagination
- **Create Transaction**: Add new transactions to accounts
- **Update Transaction**: Modify existing transactions (amount, description, category, date)

### 🏷️ Category Management
- **Get Categories**: List all transaction categories with groups, icons, and metadata
- **Get Category Groups**: View category groups with their associated categories

### 📋 Transaction Review
- **Get Transactions Needing Review**: Find transactions that need attention (uncategorized, no notes, flagged)
- **Set Transaction Category**: Assign a category to a transaction
- **Update Transaction Notes**: Add or update notes on transactions (great for receipt links)
- **Mark Transaction Reviewed**: Clear the needs_review flag on transactions

### 📦 Bulk Operations
- **Bulk Categorize Transactions**: Apply a category to multiple transactions at once

### 🔖 Tag Management
- **Get Tags**: List all available tags with colors and usage counts
- **Set Transaction Tags**: Apply tags to a transaction
- **Create Tag**: Create a new tag with custom name and color

### 🔍 Advanced Search
- **Search Transactions**: Comprehensive search with filters for merchant, category, account, tags, date ranges, and amounts
- **Get Transaction Details**: Retrieve complete details for a single transaction
- **Delete Transaction**: Remove a transaction
- **Get Recurring Transactions**: View upcoming recurring transactions

### 🤖 Transaction Rules (Auto-Categorization)
- **Get Transaction Rules**: List all auto-categorization rules
- **Create Transaction Rule**: Create rules with merchant/amount conditions to auto-categorize
- **Update Transaction Rule**: Modify existing rules
- **Delete Transaction Rule**: Remove a rule

### 🔄 Merchant & Recurring Stream Management
- **Get Merchant**: View a merchant's details including recurring transaction stream configuration
- **Update Merchant**: Modify a merchant's name and/or recurring stream settings (frequency, amount, base date)
- **Review Recurring Stream**: Accept, ignore, or reset recurring transaction streams detected by Monarch

### ✂️ Transaction Splits
- **Get Transaction Splits**: View how a transaction has been split into parts
- **Split Transaction**: Divide a single transaction into multiple parts with different categories or merchants

### 💵 Budget Management
- **Get Budgets**: Access budget information including spent amounts and remaining balances by category
- **Set Budget Amount**: Create or modify budget amounts for any category or category group

### 📈 Net Worth Tracking
- **Get Net Worth**: Track total net worth over time with daily snapshots and trend analysis
- **Get Account Balance History**: View historical balance data for any account
- **Get Net Worth by Account Type**: See net worth breakdown across account types (checking, savings, investments, etc.)

### 📊 Financial Analysis
- **Get Cashflow**: Analyze financial cashflow over specified date ranges with income/expense breakdowns
- **Get Transactions Summary**: Quick high-level statistics about your transactions
- **Get Spending Summary**: Spending breakdown by category with totals

### 🔐 Secure Authentication
- **One-Time Setup**: Authenticate once, use for weeks/months
- **MFA Support**: Full support for two-factor authentication
- **SSO/Google sign-in**: Use `monarch_login_with_token` to paste a session token from your browser
- **Session Persistence**: No need to re-authenticate frequently
- **Secure**: Credentials never pass through Claude

## 🛠️ Available Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `setup_authentication` | Get setup instructions | None |
| `check_auth_status` | Check authentication status | None |
| `get_accounts` | Get all financial accounts | None |
| `get_transactions` | Get transactions with filtering and reconciliation fields | `limit`, `offset`, `start_date`, `end_date`, `account_id`, `account_ids`, `category_ids`, `category_group_ids`, `tag_ids`, `search`, `wide_search`, `search_scan_limit`, `has_notes`, `is_split`, `is_recurring` |
| `get_budgets` | Get budget information | `start_date`, `end_date` |
| `set_budget_amount` | Set budget for a category | `amount`, `category_id`, `category_group_id`, `start_date`, `apply_to_future` |
| `get_cashflow` | Get cashflow analysis | `start_date`, `end_date` |
| `get_net_worth` | Get net worth history | `start_date`, `end_date`, `account_type` |
| `get_account_balance_history` | Get account balance history | `account_id` |
| `get_net_worth_by_account_type` | Get net worth by account type | `start_date`, `timeframe` |
| `get_account_holdings` | Get investment holdings | `account_id` |
| `create_transaction` | Create new transaction | `account_id`, `amount`, `description`, `date`, `category_id`, `merchant_name` |
| `update_transaction` | Update existing transaction | `transaction_id`, `amount`, `description`, `category_id`, `date` |
| `refresh_accounts` | Request account data refresh | `account_ids` (optional — defaults to all active, visible accounts) |
| `get_categories` | List all transaction categories | None |
| `get_category_groups` | List category groups with categories | None |
| `get_transactions_needing_review` | Get transactions needing review | `needs_review`, `days`, `uncategorized`, `no_notes` |
| `set_transaction_category` | Set category on a transaction | `transaction_id`, `category_id`, `mark_reviewed` |
| `update_transaction_notes` | Update notes on a transaction | `transaction_id`, `notes` |
| `mark_transaction_reviewed` | Mark transaction as reviewed | `transaction_id` |
| `bulk_categorize_transactions` | Categorize multiple transactions | `transaction_ids`, `category_id` |
| `get_tags` | List all tags | None |
| `set_transaction_tags` | Set tags on a transaction | `transaction_id`, `tag_ids` |
| `create_tag` | Create a new tag | `name`, `color` |
| `search_transactions` | Search transactions with filters | `search`, `category_ids`, `account_ids`, `tag_ids`, `start_date`, `end_date`, `min_amount`, `max_amount` |
| `get_transaction_details` | Get details of a transaction | `transaction_id` |
| `delete_transaction` | Delete a transaction | `transaction_id` |
| `get_recurring_transactions` | Get recurring transactions | None |
| `get_transaction_rules` | List auto-categorization rules | None |
| `create_transaction_rule` | Create an auto-categorization rule | `merchant_criteria_operator`, `merchant_criteria_value`, `set_category_id`, `add_tag_ids`, `amount_operator`, `amount_value` |
| `update_transaction_rule` | Update an existing rule | `rule_id`, `merchant_criteria_operator`, `merchant_criteria_value`, `set_category_id` |
| `delete_transaction_rule` | Delete a rule | `rule_id` |
| `get_merchant` | Get merchant details with recurring stream | `merchant_id` |
| `update_merchant` | Update merchant name/recurring stream | `merchant_id`, `name`, `is_recurring`, `frequency`, `base_date`, `amount`, `is_active` |
| `review_recurring_stream` | Set recurring stream review status | `stream_id`, `review_status` |
| `get_transaction_splits` | Get splits for a transaction | `transaction_id` |
| `split_transaction` | Split a transaction into parts | `transaction_id`, `splits` (JSON array) |
| `get_transactions_summary` | Get high-level transaction statistics | None |
| `get_spending_summary` | Get spending breakdown by category | `start_date`, `end_date`, `limit` |

## 📝 Usage Examples

### View Your Accounts
```
Use get_accounts to show me all my financial accounts
```

### Get Recent Transactions
```
Show me my last 50 transactions using get_transactions with limit 50
```

`get_transactions` returns a JSON object with `tool`, `args`, `count`, `total_count`, `truncated`, `search`, and `data` so large `agent-tools/<uuid>.txt` responses are self-describing. Transaction rows live in `data` and include `original_statement` / `plaid_description` when Monarch provides the underlying Plaid statement text, plus `currency`, `direction`, `direction_source`, `transaction_type`, `category_group`, and `category_group_id` when those values can be derived from Monarch response data. When Monarch's server-side `search` errors or returns no rows, `wide_search` scans recent transactions locally across merchant, original statement, description, notes, category, account, and tags.

### Check Spending vs Budget
```
Use get_budgets to show my current budget status
```

### Set a Budget Amount
```
Set my grocery budget to $600 for this month using set_budget_amount
```

### Apply Budget to All Future Months
```
Set my entertainment budget to $150 and apply it to all future months using set_budget_amount with apply_to_future=true
```

### Track Net Worth Over Time
```
Show my net worth trend for the past year using get_net_worth
```

### View Account Balance History
```
Show me how my savings account balance has changed over time using get_account_balance_history
```

### Net Worth Breakdown by Account Type
```
Show my net worth breakdown by account type using get_net_worth_by_account_type
```

### Analyze Cash Flow
```
Get my cashflow for the last 3 months using get_cashflow
```

### List Available Categories
```
Show me all available categories using get_categories
```

### Review Uncategorized Transactions
```
Show me transactions from the last 7 days that need review using get_transactions_needing_review
```

### Bulk Categorize Transactions
```
Categorize these three transactions as "Groceries" using bulk_categorize_transactions
```

### Tag a Transaction
```
Add the "Tax Deductible" tag to this transaction using set_transaction_tags
```

### Search for Transactions
```
Find all Amazon transactions over $50 from the last month using search_transactions
```

### View Recurring Bills
```
Show me my upcoming recurring transactions using get_recurring_transactions
```

### Create Auto-Categorization Rule
```
Create a rule to automatically categorize Amazon transactions as "Shopping" using create_transaction_rule
```

### Split a Transaction
```
Split this $100 Costco transaction into $60 for Groceries and $40 for Household using split_transaction
```

### Get Transaction Statistics
```
Give me a quick summary of my transactions using get_transactions_summary
```

### View Spending by Category
```
Show my spending breakdown by category for last month using get_spending_summary
```

### Update a Recurring Bill Amount
```
Update PennyMac's recurring stream to $1,460.93 monthly using update_merchant
```

### Review Recurring Streams
```
Approve the Netflix recurring stream using review_recurring_stream
```

## 📅 Date Formats

- All dates should be in `YYYY-MM-DD` format (e.g., "2024-01-15")
- Transaction amounts: **positive** for income, **negative** for expenses

## 🔧 Troubleshooting

### Authentication Issues
If you see "Authentication needed" errors:
1. Run the setup command: `cd /path/to/your/monarch-mcp-server && python login_setup.py` (or `uv run python login_setup.py`)
2. Restart Claude Desktop or Claude Code
3. Try using a tool like `get_accounts`

### Session Expired
Sessions last for weeks, but if expired:
1. Run the same setup command again: `python login_setup.py` (or `uv run python login_setup.py`)
2. Enter your credentials and 2FA code
3. Session will be refreshed automatically

### `'Context' object has no attribute 'elicit'`
The `monarch_login` and `monarch_login_with_token` tools require the MCP Python SDK 1.10.0 or newer (released June 2025). If your environment cached an older `mcp` install, refresh it:

```bash
uv cache clean mcp
```

Then fully quit and reopen Claude Desktop or Claude Code so it relaunches the server with a fresh resolution. As a fallback while you upgrade, run `python login_setup.py` from the repo to authenticate via the terminal.

### Common Error Messages
- **"No valid session found"**: Run `python login_setup.py` (or `uv run python login_setup.py`) 
- **"Invalid account ID"**: Use `get_accounts` to see valid account IDs
- **"Date format error"**: Use YYYY-MM-DD format for dates

## 🏗️ Technical Details

### Project Structure
```
monarch-mcp-server/
├── src/monarch_mcp_server/
│   ├── __init__.py
│   └── server.py          # Main server implementation
├── login_setup.py         # Email/password authentication script
├── pyproject.toml         # Project configuration
├── requirements.txt       # Dependencies
└── README.md             # This documentation
```

### Session Management
- Sessions are stored securely in `.mm/mm_session.pickle`
- Automatic session discovery and loading
- Sessions persist across Claude Desktop and Claude Code restarts
- No need for frequent re-authentication

### Security Features
- Credentials never transmitted through Claude Desktop or Claude Code
- MFA/2FA fully supported
- Session files are encrypted
- Authentication handled in secure terminal environment

### Recommended: require approval for mutating tools

Several tools mutate your Monarch ledger (`create_transaction`, `update_transaction`, `delete_transaction`, `bulk_categorize_transactions`, `upload_account_balance_history`, `set_transaction_tags`, `create_transaction_rule`, `update_transaction_rule`, `delete_transaction_rule`, `split_transaction`, `set_budget_amount`, `update_merchant`, `review_recurring_stream`).

Because the LLM can be influenced by data it reads back (a malicious-looking memo or merchant name in a transaction), the safest setup is to configure your MCP client to require manual approval before any mutating tool runs. In Claude Desktop and Claude Code this is the default behavior for unknown tools; keep it that way for the tools listed above rather than allow-listing them.

`bulk_categorize_transactions` and `upload_account_balance_history` also accept a `dry_run=True` argument that returns the planned changes without executing them, useful for previewing a bulk action before approving it.

## 🙏 Acknowledgments

This MCP server is built on top of the [MonarchMoneyCommunity Python library](https://github.com/bradleyseanf/monarchmoneycommunity), an actively maintained community fork of the original [MonarchMoney library](https://github.com/hammem/monarchmoney) by [@hammem](https://github.com/hammem). The community fork provides:

- Updated API endpoints for Monarch Money's current domain
- Secure authentication with MFA support
- Comprehensive API coverage for Monarch Money
- Session management and persistence

Thank you to [@hammem](https://github.com/hammem) for creating and maintaining this essential library!

## 📄 License

MIT License

## 🆘 Support

For issues:
1. Check authentication with `check_auth_status`
2. Run the setup command again: `cd /path/to/your/monarch-mcp-server && python login_setup.py`
3. Check error logs for detailed messages
4. Ensure Monarch Money service is accessible

## 🔄 Updates

To update the server:
1. Pull latest changes from repository
2. Restart Claude Desktop or Claude Code
3. Re-run authentication if needed: `python login_setup.py`
