# Schwab Advisor API Research

Research compiled January 2026. Schwab's Advisor API documentation is not publicly available - this summarizes what can be gleaned from public sources.

## Two Different API Ecosystems

Schwab has **two separate API systems**:

### 1. Individual Trader API (developer.schwab.com)
- **Audience**: Individual investors, personal trading automation
- **Access**: Self-service, free with brokerage account
- **Portal**: https://developer.schwab.com
- **Auth**: OAuth 2.0, 30-minute access token, 7-day refresh token
- **Limitation**: Must re-authenticate every 7 days (no workaround)
- **Existing libraries**: schwab-py, schwabdev, schwab-api (all on PyPI)

### 2. Advisor Services API (OpenView Gateway)
- **Audience**: RIAs, third-party vendors serving RIAs
- **Access**: Invite-only, requires partnership agreement with Schwab
- **Provider**: Performance Technologies, Inc. (PTI) - Schwab subsidiary
- **Portal**: Schwab Advisor Center (requires advisor credentials)
- **Documentation**: Not publicly available

**This project targets the Advisor Services API.**

## Advisor Services Integration Options

### Option A: Real-time API (OpenView Gateway)
- Provided by PTI (Performance Technologies Inc.)
- Real-time custody data access
- SSO integration available
- Requires integration agreement with Schwab
- Contact: Complete form at advisorservices.schwab.com

### Option B: Daily Data Files (Schwab Data Delivery)
- Batch files available daily (end of previous business day)
- Delivered via SFTP or download from Schwab Advisor Center
- Multiple file formats available
- Setup takes 3-6 weeks

### Option C: Third-party Aggregators
- BridgeFT WealthTech API
- Panoramix
- Other approved vendors (370+ integrations available)

## Schwab Data Delivery File Formats

Three file format families are available:

### BD Core Files (CRS) - Recommended
Filename pattern: `CRSyyyymmdd.*`

| Extension | Content |
|-----------|---------|
| .ACC | Account information |
| .RPS | Position details (reconciliation) |
| .SEC | Security and pricing data |
| .TRN | Transaction records |
| .ULT/.ULN | Cost basis reconciliation |

### Generic Centerpiece Files (CS)
Filename pattern: `CSmmddyy.*`

| Extension | Content |
|-----------|---------|
| .BLD/.BKB | Consolidated position, security, price, account data |
| .TRN/.BAK | Transaction records |
| .PRI | Price information |

### Portfolio Center Enhanced Files (PC)
Available upon request only.

| Extension | Content |
|-----------|---------|
| .SLB | Position/build file with portfolio and security details |
| .SLT | Daily transaction records |

## Trade File Format (for submitting orders)

CSV format with the following characteristics:
- Comma-delimited (.csv)
- Minimum 6 fields, up to 18 fields
- Empty fields must have comma placeholder
- Data in CAPITAL letters
- Max 10,000 orders per file
- Default to market orders if no price specified

Detailed field specification available in Tamarac documentation:
https://support.tamaracinc.com/help/content/resources/pdf/rebalancing/schwabwebtrading_all_fileformats_v5_9.pdf

## Individual Trader API Endpoints (for reference)

From schwab-py documentation - the Advisor API likely has similar but expanded endpoints:

### Accounts
- `get_account_numbers()` - Get account hash mappings
- `get_account(account_hash, fields)` - Single account data
- `get_accounts(fields)` - All linked accounts

### Positions & Transactions
- Positions included in account data with `fields=POSITIONS`
- `get_transaction(account_hash, transaction_id)`
- `get_transactions(account_hash, start_date, end_date, types, symbol)`

Transaction types: TRADE, RECEIVE_AND_DELIVER, DIVIDEND_OR_INTEREST, ACH_RECEIPT, ACH_DISBURSEMENT, CASH_RECEIPT, CASH_DISBURSEMENT, ELECTRONIC_FUND, WIRE_OUT, WIRE_IN, JOURNAL, MEMORANDUM, MARGIN_CALL, MONEY_MARKET, SMA_ADJUSTMENT

### Orders
- `place_order(account_hash, order_spec)`
- `get_orders_for_account(account_hash, ...)`
- `get_orders_for_all_linked_accounts(...)`
- `cancel_order(order_id, account_hash)`
- `replace_order(account_hash, order_id, order_spec)`

### Market Data
- `get_quote(symbol)` / `get_quotes(symbols)`
- `get_price_history(symbol, ...)` - Various intervals back to 1985
- `get_option_chain(symbol, ...)`
- `get_instruments(symbols, projection)`
- `get_movers(index, sort_order, frequency)`
- `get_market_hours(markets, date)`

## Authentication Flow (Individual API)

1. Register at developer.schwab.com
2. Create application, get client_id and client_secret
3. Set callback URL (must be HTTPS, localhost OK for dev)
4. OAuth 2.0 authorization code flow
5. Access token expires in 30 minutes (auto-refresh)
6. Refresh token expires in 7 days (requires re-auth)

## Next Steps

1. Obtain Schwab Advisor Center credentials
2. Access OpenView Gateway documentation from within Advisor Center
3. Determine which integration method is appropriate:
   - Real-time API for live data
   - Data Delivery for batch processing
4. If using Data Delivery, request specific file format documentation

## Resources

- [Schwab Advisor Services - API Integration](https://advisorservices.schwab.com/managing-your-business/tech-integration/api-integration)
- [Schwab Advisor Services - Daily Data Files](https://advisorservices.schwab.com/managing-your-business/tech-integration/daily-data-files)
- [Schwab Developer Portal (Individual)](https://developer.schwab.com/)
- [schwab-py Documentation](https://schwab-py.readthedocs.io/)
- [Schwab Trade File Formats (Tamarac)](https://support.tamaracinc.com/help/content/resources/pdf/rebalancing/schwabwebtrading_all_fileformats_v5_9.pdf)
