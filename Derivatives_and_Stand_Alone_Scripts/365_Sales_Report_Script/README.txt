
O365_Sales_Report_Graph.ps1
Weekly send/receive report using EXO CBA + Microsoft Graph app-only (certificate auth)
Anchor group: sales@vadtek.com (synced DL)
Author: Dan Damit (https://github.com/dan-damit)

Prereqs needed on the device running the script for the script to work:
- ExchangeOnlineManagement module
- Microsoft.Graph module
- The Authentication Certificate installed in 'Cert:\LocalMachine\My' Store to run as SYSTEM in PDQ or from whatever server/workstation we select to run the script.
- Currently this Cert handles authentication: $CertThumb = "F226D64FF93DE27A1CFC9F9078829FBBD5B21770"

Additional Notes:
- _SalesEmailReport_Exclusions.txt is the file that the scripts looks at as emails to exclude from the report.
- Small adjustments will need to be made when UTILITY-1 goes away (e.g. like $WorkingDir).
