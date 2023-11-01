# Visited Websites by Browser

The following KQL Queries using Microsoft's Advanced Threat Hunting functionality, will allow you to view websites visited on a managed device by browser type.

## Microsoft Edge

```powerquery
// Detect sites visited using Microsoft Edge
// Note: Device ID must be filled in

DeviceNetworkEvents
    // Timeframe, default 7 days
    | where Timestamp > ago(7d)
    // Device ID: Locate this via Entra ID (Azure Active Directory)
    | where DeviceId == "" // Device Id
    | where InitiatingProcessFileName == "msedge.exe"
    // Summarize by Device Name, Timestamp, Remote IP Address, Remote Port, and Remote URL
    | summarize by DeviceName, Timestamp, RemoteIP, RemotePort, RemoteUrl
```

## Google Chrome

```powerquery
// Detect sites visited using Microsoft Edge
// Note: Device ID must be filled in

DeviceNetworkEvents
    // Timeframe, default 7 days
    | where Timestamp > ago(7d)
    // Device ID: Locate this via Entra ID (Azure Active Directory)
    | where DeviceId == "" // Device Id
    | where InitiatingProcessFileName == "chrome.exe"
    // Summarize by Device Name, Timestamp, Remote IP Address, Remote Port, and Remote URL
    | summarize by DeviceName, Timestamp, RemoteIP, RemotePort, RemoteUrl
```
