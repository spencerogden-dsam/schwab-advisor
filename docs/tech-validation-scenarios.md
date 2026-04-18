# Schwab Technical Validation Scenarios — Case 9850

Mirror of `tech-validation-scenarios.xlsx` (from Schwab Participant Portal, Apr 17 2026).
Kept as markdown so scenarios are searchable in-repo.

## Required

| ID | Scenario | Expected | Error Code |
|----|----------|----------|------------|
| RE-0001 | Verify that calls come across with unique Correlator IDs | A unique correlator ID is passed on each service call. Integration Specialist: This can be found in Extended_Fields.ServiceInfo.InternalCorrId | — |

## Enrollment

| ID | Scenario | Expected | Error Code |
|----|----------|----------|------------|
| ENR-0001 | Verify the participant can call the Consent & Grant (CAG) process | The participant should get an access token. | — |
| ENR-0002 | Verify the appropriate UI pop-up displays when the Enrollment service is called | The Schwab Advisor Center® enrollment UI is properly presented in a new window. | — |
| ENR-0003 | Verify successful enrollment for a user providing a valid SAC User ID and password and OTP if applicable | The service returns the appropriate error message and a similar message is displayed in the Consuming application. | Description: "You have successfully acknowledged and agreed to the Schwab OpenView Gateway Advisor Enrollment Use Agreement" |
| ENR-0004 | Verify that the user can obtain a refresh token | The user should be able to get a refresh token after the access token expires in 3600 seconds or if they manually update the token | — |

## Alerts

| ID | Scenario | Expected | Error Code |
|----|----------|----------|------------|
| AL-0001 | Verify the user is able to bring back alerts for accounts that they have access to | User should see a list of complete alerts for all accounts associated with their firm. | — |
| AL-0002 | Verify that the user can pass the Schwab-Client-Ids filter: account, masterAccount | User is able to retrieve all alerts using the filter | — |
| AL-0003 | Verify that the user can pass the filter[startDate] (The earliest and default date is 3 years prior) | User is able to retrieve all alerts using the filter | — |
| AL-0004 | Verify that the user can pass the filter[endDate] (The default date is the current date.) | User is able to retrieve all alerts using the filter | — |
| AL-0005 | Verify that the user can pass the filter[type] (All returned if the filter is not passed.) | User should see lists of alerts for each filter. | — |
| AL-0006 | Verify that the user can pass the filter[status]: New, Viewed, ResponseSent (All returned if the filter is not passed. | User should see lists of alerts for each filter. | — |
| AL-0007 | Verify that the user can pass the filter[isArchived]: true, false (All returned if the filter is not passed. | User should see lists of alerts for each filter. | — |
| AL-0008 | Verify that the user can use the page[cursor] value | The service returns the starting record. | — |
| AL-0009 | Verify that the user can use the page[limit] value | The service returns the number of records (maximum value: 500) | — |
| AL-0010 | Verify the user can use sortBy: CreatedDate, FormattedAccount, FormattedMasterAccount, Priority, ReplyType, Status, Subject, Type (default value: CreatedDate) | The service returns the account according to the storyBy | — |
| AL-0011 | Verify the user can use sortDirection: Asc, Desc (default value: Asc) | The service returns the account according to the storyDirection | — |
| AL-0012 | Verify that the user can use the showAccount value: Mask, Show (default value: Mask) | The list of accounts is either masked or shown | — |
| AL-0013 | Verify that the appropriate error message is returned when a user sends a bad correlator ID | The service returns the appropriate error message and a similar message is displayed in the Consuming application. | Status:400 Title: Bad Request Detail: The Schwab-Client-CorrelId Field is required |
| AL-0014 | Verify that the appropriate error message is returned when a user does not have the necessary access to view the requested information. | The service returns the appropriate error message and a similar message is displayed in the Consuming application. | Status:401 Title: Unauthorized Code: SEC-0001 |
| AL-0015 | Verify that the appropriate error message is returned when one or more of the requested resources were not found. | The service returns the appropriate error message and a similar message is displayed in the Consuming application. | Status:404 Title: Not Found Code: SEC-0002 |
| ALID-0001 | Verify the user is able to bring back alert details for accounts that they have access to | User should see a list of complete alert details for all accounts associated with their firm. | — |
| ALID-0002 | Verify that the user can use the showAccount value: Mask, Show (default value: Mask) | The list of account alert details is either masked or shown | — |
| ALARCHPOST-0001 | Verify the user is able to archive alerts for accounts that they have access to | User should be able to archive alerts for accounts associated with their firm. (Please do not archive all accounts) | — |

## Status

| ID | Scenario | Expected | Error Code |
|----|----------|----------|------------|
| ST-0001 | Verify the user can retrieve events from a status feed. | The user is able to retrieve the events from a status feed successfully. | — |
| ST-0002 | Verify the user is able to pass the feed_id in the status call. | The user is able to send the feed_id in the status call. | — |
| ST-0003 | Verify the user is able to pass the object_id in the status call | The user is able to send the object_id in the status call. | — |
| ST-0004 | Verify that the appropriate error message is returned when a user sends a bad correlator ID | The service returns the appropriate error message and a similar message is displayed in the Consuming application. | Status:400 Title: Bad Request Detail: The Schwab-Client-CorrelId Field is required |
| ST-0005 | Verify that the appropriate error message is returned when a user does not have the necessary access to view the requested information. | The service returns the appropriate error message and a similar message is displayed in the Consuming application. | Status:401 Title: Unauthorized Code: SEC-0001 |
| ST-0006 | Verify that the appropriate error message is returned when one or more of the requested resources were not found. | The service returns the appropriate error message and a similar message is displayed in the Consuming application. | Status:404 Title: Not Found Code: SEC-0002 |
| STFDPOST-0001 | Verify the user is able to create a status feed. | The user is able to create a status feed successfully. | — |
| STFDPOST-0002 | Verify the user is able to send the field: status Action Needed, Canceled, In Process, New, Resolved | The service returns the status information according to the field. | — |
| STFDPOST-0003 | Verify the user is able to send the field: masterAccounts | The service returns the status information according to the field. | — |
| STFDPOST-0004 | Verify the user is able to send the field: accounts | The service returns the status information according to the field. | — |
| STFDPOST-0005 | Verify the user is able to send the field: startDate The earliest and default date supported is 90 days prior. | The service returns the status information according to the field. | — |
| STFDPOST-0006 | Verify the user is able to send the field: endDate (default value: current date) | The service returns the status information according to the field. | — |
| STFDPOST-0007 | Verify the user is able to send the field: timeFrame CreatedDate, LasteUpdatedDate (default value: CreatedDate) | The service returns the status information according to the field. | — |
| STFDPOST-0008 | Verify the user is able to send the field: categories Account Maintenance, Account Open, Alternative Investment, Cost Basis, Digital Envelope, Estates, Move Money, Pledged Asset Agreement, Transfer of Assets (All will be returned if the filter is not passed) | The service returns the status information according to the field. | — |
| STFDPOST-0009 | Verify the user is able to send the field: myqCaseId (example WI-123456) | The service returns the status information according to the field. | — |
| STFDPOST-0010 | Verify the user is able to send the field: serviceRequestConfirmationID (example SR813637257) | The service returns the status information according to the field. | — |
| STFDPOST-0011 | Verify the user is able to send the field: actionCenterEnvelopeId (example 842993565) | The service returns the status information according to the field. | — |
| STFDPOST-0012 | Verify the user is able to send the field: includeAllEvents true, false (default value: false) | The service returns the status information according to the field. | — |
| STFDPOST-0013 | Verify the user is able to send the field: firstPageOnly true, false (default: false) this indicated whether 1000 or 2000 events should be returned | The service returns the status information according to the field. | — |
| STFDPOST-0014 | Verify that the user can use the showAccount value: Mask, Show (default value: Mask) | The list of accounts is either masked or shown | — |
