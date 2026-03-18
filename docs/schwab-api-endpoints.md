# Schwab Advisor Services API Reference

Extracted from Schwab Developer Portal (March 2026).

**Base URL:** `https://api.schwabapi.com/as-integration/bulk/v2` (production)  
**Sandbox:** `https://sandbox.schwabapi.com/as-integration/bulk/v2`

**Required headers:**
- `Authorization: Bearer {access_token}`
- `Schwab-Client-CorrelId: {uuid4}`
- `Schwab-Resource-Version: 1`
- `Accept: application/json`

---

## Table of Contents

- [Account BLocks](#account-blocks) (2 endpoints)
- [Account Inquiry](#account-inquiry) (3 endpoints)
- [Account Preferences and Authorizations](#account-preferences-and-authorizations) (1 endpoints)
- [Account Syncronization](#account-syncronization) (1 endpoints)
- [Address Change](#address-change) (3 endpoints)
- [Alerts](#alerts) (4 endpoints)
- [Balances](#balances) (2 endpoints)
- [Client Inquiry](#client-inquiry) (1 endpoints)
- [Cost Basis](#cost-basis) (4 endpoints)
- [Daily Data](#daily-data) (1 endpoints)
- [Digital Account Open](#digital-account-open) (1 endpoints)
- [Document Preferences](#document-preferences) (1 endpoints)
- [Man Fee File Upload](#man-fee-file-upload) (1 endpoints)
- [Positions](#positions) (2 endpoints)
- [Profiles](#profiles) (2 endpoints)
- [Reports](#reports) (2 endpoints)
- [Service Request](#service-request) (2 endpoints)
- [Standing Authorizations](#standing-authorizations) (2 endpoints)
- [Status](#status) (4 endpoints)
- [Trading File Upload](#trading-file-upload) (2 endpoints)
- [Trading](#trading) (4 endpoints)
- [Transactions](#transactions) (2 endpoints)
- [User Authorization](#user-authorization) (1 endpoints)
- [feature Enrollment](#feature-enrollment) (2 endpoints)
- [iRebal](#irebal) (10 endpoints)
- [AS Account](#as-account) (3 endpoints)

---

## Account BLocks

### `GET /account-block-numbers`

### `POST /account-block-numbers`

**Data Models:** `AccountBlockGetResponse`, `AccountBlockGetResponseAccount`, `AccountBlockGetResponseAttributes`, `AccountBlockGetResponseData`, `AccountBlockPostRequest`, `AccountBlockPostRequestAttributes`, `AccountBlockPostRequestData`, `AccountBlockPostResponse`, `AccountBlockPostResponseAccount`, `AccountBlockPostResponseAttributes`, `AccountBlockPostResponseData`, `AvailableAccounts`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `MaxLimit`

---

## Account Inquiry

### `GET /master-accounts`

### `GET /accounts`

### `POST /account-owners/list`

**Data Models:** `AccountOwners`, `AccountOwnersListPostRequest`, `AccountOwnersListPostResponse`, `AccountOwnersListPostResponseData`, `AccountOwnersListPostResponseDataAttributes`, `AccountsGetResponseDataAttributes`, `AccountsGetResponseDataV1`, `AccountsGetResponseDataV2`, `AccountsGetResponseV1`, `AccountsGetResponseV2`, `Client`, `Count`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ErrorsList`, `FormattedAccount`, `MasterAccountsGetResponse`, `MasterAccountsGetResponseData`, `MasterAccountsGetResponseDataAttributes`, `Paging`

---

## Account Preferences and Authorizations

### `POST /preferences-and-authorizations/list`

**Data Models:** `AccountPreferences`, `Authorizations`, `CashAndMarginPreferences`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ErrorsList`, `FormattedAccount`, `PreferencesAndAuthorizations`, `PreferencesAndAuthorizationsListPostRequest`, `PreferencesAndAuthorizationsListPostResponse`, `PreferencesAndAuthorizationsListPostResponseData`, `PreferencesAndAuthorizationsListPostResponseDataAttributes`

---

## Account Syncronization

### `GET /account-sync`

**Data Models:** `AccountSyncGetResponse`, `AccountSyncGetResponseData`, `Count`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `Paging`

---

## Address Change

### `GET /address-changes/{action_id}`

### `GET /address-changes`

### `POST /address-changes`

**Data Models:** `AccountHolderAddress`, `AddressChangesByActionIdGetResponse`, `AddressChangesGetResponse`, `AddressChangesGetResponseData`, `AddressChangesGetResponseDataAttributes`, `AddressChangesGetResponseDataRelationships`, `AddressChangesPostRequest`, `AddressChangesPostResponse`, `AddressChangesPostResponseData`, `AddressChangesPostResponseDataAttributes`, `AddressLinks`, `Agent`, `BaseAddress`, `Contact`, `Customer`, `CustomerAttributes`, `CustomerSearchCriteria`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `OrganizationAddress`, `OrganizationProfile`, `OriginalAddress`, `OtherAccountHolder`, `TrustProfiles`, `Trustee`, `UpdatedAddress`, `UpdatedCustomerAddress`, `UpdatedOrganizationAddress`

---

## Alerts

### `GET /alerts`

### `GET /alerts/detail/{alert_id}`

### `POST /alerts/archive`

### `PATCH /alerts/{alert_id}`

**Data Models:** `AlertAttributes`, `Alerts`, `AlertsArchivePostRequest`, `AlertsArchivePostResponse`, `AlertsArchivePostResponseData`, `AlertsArchivePostResponseDataAttributes`, `AlertsDetailGetResponse`, `AlertsDetailGetResponseData`, `AlertsDetailGetResponseDataAttributes`, `AlertsGetResponse`, `AlertsGetResponseData`, `AlertsPatchRequest`, `ArchiveDetail`, `Count`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `Paging`, `StatusHistory`

---

## Balances

### `GET /balances/detail`

### `POST /balances/list`

**Data Models:** `Balance`, `BalancesDetailGetResponse`, `BalancesDetailGetResponseData`, `BalancesDetailGetResponseDataAttributes`, `BalancesListPostRequest`, `BalancesListPostResponse`, `BalancesListPostResponseData`, `BalancesListPostResponseDataAttributes`, `Count`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ErrorsList`, `FormattedAccount`, `TotalBalance`

---

## Client Inquiry

### `GET /client-inquiries`

**Data Models:** `ClientInquiryGetResponse`, `ClientInquiryGetResponseData`, `Count`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`

---

## Cost Basis

### `GET /cost-basis/account-preferences`

### `GET /cost-basis/rgl-transactions`

### `GET /cost-basis/ugl-positions`

### `POST /cost-basis/ugl-position-lots/list`

**Data Models:** `AccountPreferencesDetail`, `AccountPreferencesGetResponse`, `AccountPreferencesGetResponseData`, `AccountPreferencesSummary`, `Count`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ErrorsList`, `Notes`, `Paging`, `RglCount`, `RglPaging`, `RglTransaction`, `RglTransactionLot`, `RglTransactionsGetResponse`, `RglTransactionsGetResponseData`, `RglTransactionsGetResponseDataAttributes`, `RglTransactionsSummary`, `UglPosition`, `UglPositionDetail`, `UglPositionLot`, `UglPositionLotsListPostRequest`, `UglPositionLotsListPostResponse`, `UglPositionLotsPostResponseData`, `UglPositionLotsPostResponseDataAttributes`, `UglPositionsGetResponse`, `UglPositionsGetResponseData`, `UglPositionsGetResponseDataAttributes`, `UglPositionsSummary`

---

## Daily Data

### `GET /account-balances-positions`

**Data Models:** `AccountBalancesPositionsGetResponse`, `AccountBalancesPositionsGetResponseData`, `Balances`, `Count`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `Paging`, `Position`, `Security`

---

## Digital Account Open

### `POST /account-open-contacts`

**Data Models:** `AccountOpenContactsPostRequest`, `Address`, `Contact`, `DirectorDetails`, `Employment`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `Identification`, `Name`, `PhoneNumber`

---

## Document Preferences

### `POST /document-preferences/list`

**Data Models:** `CommunicationDetail`, `Delivery`, `DocumentDelivery`, `DocumentPreferences`, `DocumentPreferencesListPostRequest`, `DocumentPreferencesListPostResponse`, `DocumentPreferencesListPostResponseData`, `DocumentPreferencesListPostResponseDataAttributes`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ErrorsList`, `FormattedAccount`, `ManagedAccount`, `Recipient`, `ReportPreferences`

---

## Man Fee File Upload

### `POST /upload-manfees`

**Data Models:** `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `UploadManFeesPostRequest`

---

## Positions

### `GET /positions/detail`

### `POST /positions/list`

**Data Models:** `Count`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ErrorsList`, `FormattedAccount`, `ListPosition`, `Paging`, `Position`, `PositionsDetailGetResponse`, `PositionsDetailGetResponseData`, `PositionsDetailGetResponseDataAttributes`, `PositionsListPostRequest`, `PositionsListPostResponse`, `PositionsListPostResponseData`, `PositionsListPostResponseDataAttributes`, `TotalListPositions`, `TotalPositions`

---

## Profiles

### `POST /profiles/list`

### `GET /profiles/account-holders`

**Data Models:** `Account`, `Employment`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ErrorsList`, `FormattedAccount`, `FormattedDateOfBirth`, `FormattedTaxpayerId`, `Holder`, `MailingAddress`, `Profile`, `ProfileListPostResponseData`, `ProfileListPostResponseDataAttributes`, `ProfilesAccountHoldersGetResponse`, `ProfilesAccountHoldersGetResponseData`, `ProfilesAccountHoldersGetResponseDataAttributes`, `ProfilesListPostRequest`, `ProfilesListPostResponse`

---

## Reports

### `GET /reports`

### `GET /reports/pdf`

**Data Models:** `Count`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ErrorsList`, `FormattedAccount`, `Paging`, `Report`, `ReportsGetResponse`, `ReportsGetResponseData`, `ReportsGetResponseDataAttributes`, `ReportsPdfGetResponse`, `ReportsPdfGetResponseData`, `ReportsPdfGetResponseDataAttributes`

---

## Service Request

### `GET /service-requests`

### `POST /service-requests`

**Data Models:** `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ServiceRequestAttachment`, `ServiceRequestFiles`, `ServiceRequestsGetResponse`, `ServiceRequestsGetResponseData`, `ServiceRequestsGetResponseDataAttributes`, `ServiceRequestsPostRequest`, `ServiceRequestsPostResponse`, `ServiceRequestsPostResponseData`, `ServiceRequestsPostResponseDataAttributes`, `SubTopic`

---

## Standing Authorizations

### `GET /standing-instructions`

### `GET /standing-instructions/{id}`

**Data Models:** `Address`, `CounterParty`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `InstructionId`, `InstructionsDetail`, `InstructionsSummary`, `StandingInstructionCommon`, `StandingInstructionDetail`, `StandingInstructionList`, `StandingInstructionSummary`, `TransactionType`

---

## Status

### `POST /status-feed`

### `GET /status-feed/{feed_id}`

### `GET /status-feed/{feed_id}/status-objects/{object_id}/status-events`

### `POST /status-events`

**Data Models:** `Accounts`, `ActionCenterEnvelopeId`, `AdditionalInfo`, `Categories`, `ClientInfo`, `ConfidentialInfo`, `Count`, `Document`, `EndDate`, `EntryChannel`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ErrorsList`, `FormattedAccount`, `FormattedMasterAccount`, `IncludeAllEvents`, `MasterAccounts`, `MyqCaseId`, `ProcessDetail`, `ServiceRequestConfirmationId`, `ShowAccount`, `StartDate`, `StartDateV1`, `Status`, `StatusEvent`, `StatusEventsPostRequest`, `StatusEventsPostResponse`, `StatusEventsPostResponseData`, `StatusEventsPostResponseDataAttributes`, `StatusFeedByFeedIdGetResponse`, `StatusFeedByFeedIdGetResponseData`, `StatusFeedByFeedIdGetResponseMeta`, `StatusFeedByFeedIdObjectIdGetResponse`, `StatusFeedByFeedIdObjectIdGetResponseData`, `StatusFeedByFeedIdObjectIdGetResponseDataAttributes`, `StatusFeedPostRequestV1`, `StatusFeedPostRequestV2`, `StatusFeedPostResponse`, `StatusFeedPostResponseData`, `StatusFeedPostResponseDataAttributes`, `StatusFeedPostResponseMeta`, `StatusObject`, `StatusObjectId`, `StatusObjectPost`, `TimeFrame`, `TimeFrameV1`, `Timestamp`, `UpsTrackingInfo`

---

## Trading File Upload

### `POST /upload-blotters`

### `POST /upload-allocations`

**Data Models:** `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `UploadAllocationsPostRequest`, `UploadBlottersPostRequest`

---

## Trading

### `POST /orders`

Validates/Submits Orders

### `PUT /orders`

Cancels and Replaces Orders

### `DELETE /orders`

Cancels Orders

### `POST /orders/status`

**Data Models:** `Account`, `BaseOrderItem`, `CancelOrder`, `CancelOrdersRequest`, `ClientOrderIdentifier`, `CommonOrderItem`, `CommonOrderStatusDetails`, `CommonOrdersRequest`, `ContingentId`, `DividendReinvestment`, `EquityDividendReinvestOption`, `EquityOrderItem`, `EquityOrderItemDetail`, `EquityOrderQualifier`, `EquityOrderType`, `EquityTrailingStopOrderType`, `EquityTransactionType`, `ErrorInfo`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse401`, `ErrorResponse404`, `GenericErrorResponse`, `LimitOrderType`, `LotInfo`, `MarketOrderType`, `MasterAccount`, `ModifyEquityOrderItem`, `ModifyOrderCommonAttributes`, `ModifyOrdersRequest`, `MutualFundAmountType`, `MutualFundBuyTransactionType`, `MutualFundDividendReinvestOption`, `MutualFundLongtermCapitalGainsOption`, `MutualFundOrderItem`, `MutualFundOrderItemDetail`, `MutualFundSellTransactionType`, `MutualFundSwapTransactionType`, `MutualFundTransactionType`, `OrderAmount`, `OrderDateTime`, `OrderDuration`, `OrderNumber`, `OrderPrice`, `OrderStatus`, `OrderType`, `OrdersResponse`, `OrdersResult`, `OrdersStatusRequest`, `OrdersStatusResponse`, `SecurityIdentifier`, `SecurityIdentifierTypeCode`, `SecurityType`, `StopLimitOrderType`, `StopOrderType`, `SubmitOrdersRequest`, `TaxLot`, `TaxLotMethod`, `TrailingStopMethod`, `TrailingStopType`, `ValidationError`

---

## Transactions

### `GET /transactions`

### `GET /transactions/detail`

**Data Models:** `Count`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `Paging`, `Transaction`, `TransactionAttributes`, `TransactionsDetailGetResponse`, `TransactionsDetailGetResponseData`, `TransactionsGetResponse`, `TransactionsGetResponseData`

---

## User Authorization

### `GET /authorizations`

**Data Models:** `Authorization`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `UserAuthorizationGetResponse`, `UserAuthorizationGetResponseData`

---

## feature Enrollment

### `GET /data-delivery-enrollments`

### `PUT /data-delivery-enrollments`

**Data Models:** `DataDeliveryEnrollmentsGetResponse`, `DataDeliveryEnrollmentsGetResponseAttributes`, `DataDeliveryEnrollmentsPutRequest`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`

---

## iRebal

### `GET /blended-models`

### `POST /blended-models`

### `PUT /blended-models/{id}`

### `GET /models`

### `POST /models`

### `PUT /models/{id}`

### `GET /portfolios`

### `POST /portfolios`

### `PUT /portfolios/{id}`

### `DELETE /portfolios/{id}`

**Data Models:** `BlendedModelGetResponse`, `BlendedModelGetResponseAttributes`, `BlendedModelGetResponseComponentModel`, `BlendedModelGetResponseComponentModels`, `BlendedModelGetResponseData`, `BlendedModelGetResponseSecurities`, `BlendedModelPostRequest`, `BlendedModelPostRequestData`, `BlendedModelPostResponse`, `BlendedModelPostResponseData`, `BlendedModelPutRequest`, `BlendedModelPutRequestData`, `BlendedModelRequestAttributes`, `BlendedModelRequestComponentModel`, `BlendedModelRequestComponentModels`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `ModelGetResponse`, `ModelGetResponseAttributes`, `ModelGetResponseData`, `ModelGetResponseSecurities`, `ModelPostRequest`, `ModelPostRequestAttributes`, `ModelPostRequestData`, `ModelPostRequestSecurities`, `ModelPostResponse`, `ModelPostResponseData`, `ModelPutRequest`, `ModelPutRequestData`, `ModelPutRequestSecurities`, `PartialErrorBlended`, `PartialErrorModel`, `PartialErrorPortfolio`, `PortfolioGetDataResponse`, `PortfolioGetResponse`, `PortfolioPostRequest`, `PortfolioPostRequestData`, `PortfolioPostResponse`, `PortfolioPostResponseData`, `PortfolioPutRequest`, `PortfolioPutRequestData`

---

## AS Account

### `GET /account-profiles`

**Query Parameters:**

| Parameter | Type | Required |
|-----------|------|----------|
| `page[cursor]` | string | No |
| `page[limit]` | integer | No |
| `includeTotalCount` | boolean | No |
| `showAccount` | string | No |

### `GET /account-roles`

### `GET /account-rmd`

**Data Models:** `AccountProfilesGetResponse`, `AccountProfilesGetResponseData`, `AccountRMDGetResponse`, `AccountRMDGetResponseData`, `AccountRegistrationType`, `AccountRolesGetResponse`, `AccountRolesGetResponseData`, `AccountTitle1`, `AccountTitle2`, `AccountTitle3`, `Address`, `BusinessPhone`, `Count`, `DocumentDelivery`, `EmailAddress`, `ErrorInfo400`, `ErrorInfo401`, `ErrorInfo404`, `ErrorInfoSource`, `ErrorResponse400`, `ErrorResponse401`, `ErrorResponse404`, `FirstName`, `FormattedAccount`, `FormattedDateOfBirth`, `FormattedMasterAccount`, `FormattedPrimaryMasterAccount`, `HomePhone`, `LastName`, `MasterAccount`, `MasterAccountType`, `MiddleName`, `Paging`, `Roles`

---

