# Schwab Technical Validation — Email Chain

Correspondence with Drew Keating (Sr. Manager, Advisor Services, Advisor Direct
Integrations) and Jodie Falcon at Schwab, leading up to the technical
validation for our first integration (Alerts + Status APIs). Validation
scenarios are tracked in case **# 9850** on the Schwab Participant Portal.

Kept for reference alongside `tech-validation-scenarios.xlsx` so the full
context is in-repo.

---

## 1. Initial Goals (outbound) — Tue, Mar 31 2026, 8:29 PM EDT

**From:** Spencer Ogden <spencer@dockstreet.com>
**To:** Drew Keating <Drew.Keating@schwab.com>
**Subject:** Initial Goals

> Hi Drew,
>
> Here are some things I would like to accomplish with our initial role out:
>
> - Download all account profiles (assume this includes things like
>   Beneficiaries, Checkwriting abilities etc)
> - Poll API for new alerts
> - Get schedule transfers from Move Money
> - Get cost basis settings for all accounts
> - Get MoneyLink SLOAs for all accounts in a master
> - Download transactions and balances intra day

---

## 2. API product mapping + meeting recap — Wed, Apr 1 2026, 1:37 PM EDT

**From:** Drew Keating <Drew.Keating@schwab.com>
**To:** Spencer Ogden
**Cc:** Jodie Falcon <Jodie.Falcon@schwab.com>
**Subject:** RE: Initial Goals

Drew confirmed the **Accounting Method** is included in the Cost Basis API
response, and mapped the initial goals to specific APIs:

| Goal | API product |
|------|-------------|
| Download all account profiles (Beneficiaries, Checkwriting, etc.) | **Profiles, Account Roles/Bene** |
| Poll API for new alerts | **Alerts, Status** |
| Get scheduled transfers from Move Money | **Move Money Activity** |
| Get cost basis settings for all accounts | **Cost Basis / Preferences** |
| Get MoneyLink SLOAs for all accounts in a master | **SLOA** (Standing Authorizations) |
| Download transactions and balances intra-day | **RT Balances, Transactions** |

### Meeting recap — Schwab & Dock Street | API Project Planning

Aligning with Dock Street on an effective API development and promotion
strategy. Balancing broad sandbox exploration with a more controlled, phased
approach to production promotion.

**Key points & decisions**

- Dock Street can continue using a sandbox app with many APIs for learning
  and experimentation, while creating smaller, focused apps/projects for APIs
  intended for production.
- API work should be broken into logical projects (e.g., **Alerts & Status
  first**) to avoid delaying production due to all-or-nothing technical
  validation.
- The existing participant portal project (PR 2279) can be reused, updated,
  or cloned depending on how Dock Street chooses to scope future work.
- Move Money Activity, Alerts, Status, Profiles, Cost Basis, Balances, and
  Transactions APIs were reviewed against Dock Street use cases (Slack
  alerts, Wealthbox CRM visibility, workflow automation).

**Next steps**

- Send a follow-up email to Dock Street summarizing recommended APIs and
  include the participant portal link.
- Dock Street to decide how to group APIs into one or more projects and
  update or create participant portal projects accordingly.
- When ready, Jodie will provide **technical validation scenarios**; Dock
  Street will record and submit a walkthrough for review prior to promotion.

**Open items**

- Final confirmation of API grouping and phase sequencing.
- Validation that the Cost Basis Preferences API fully meets Dock Street's
  audit and reporting needs.

---

## 3. Ready for Alerts/Status review (outbound) — Thu, Apr 16 2026, 9:07 PM EDT

**From:** Spencer Ogden
**To:** Drew Keating
**Cc:** Jodie Falcon
**Subject:** RE: Initial Goals

> Hi Drew,
>
> I think we are ready for a review on our Alerts/Status implementation to
> promote to production. A brief outline of what we have:
>
> - A Python module to handle calls to the APIs and OAuth
> - Middleware running on fly.io to handle OAuth callbacks and endpoints for
>   interacting with the API
> - A Zapier app which will poll the Alerts and Status endpoints every few
>   minutes to pick up new items
>
> When could we schedule that and what should I have prepared?

---

## 4. Validation scenarios delivered — Fri, Apr 17 2026, 10:20 AM EDT

**From:** Drew Keating
**To:** Spencer Ogden
**Cc:** Jodie Falcon
**Subject:** RE: Initial Goals

> Hi Spencer, Jodie has added the **technical validation scenarios** we need
> to see to **case # 9850** on the Participant Portal. Can record the session
> going through the scenarios and upload to the case? If not, we'll find some
> time on the calendar to go through it together.
>
> If you have questions, please put those on the case so Jodie and team can
> respond.

**Participant Portal:** <https://sit.my.site.com/SOVGParticipants/s/>

Validation scenarios → `tech-validation-scenarios.xlsx` (this repo) →
mirrored as `tech-validation-scenarios.md` for searchability.
