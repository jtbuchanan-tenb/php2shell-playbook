## Microsoft Defender XDR and Microsoft Sentinel (KQL)

Behavior-based. No PHP2Shell IOCs have been published; these searches look for what exploitation does, not for known indicators.

These run in Defender XDR advanced hunting, or in Sentinel when the Defender XDR connector streams the `Device*` tables. Check the field names against your data before you trust an empty result.

### 1. A PHP worker starts a shell, curl or wget

```kql
DeviceProcessEvents
| where Timestamp >= datetime($start)
| where InitiatingProcessFileName has_any ("php-fpm", "php-cgi", "httpd", "apache2")
    or InitiatingProcessFileName matches regex @"^php[0-9.]*$$"
| where FileName in~ ("sh", "bash", "dash", "zsh", "curl", "wget")
$kql_filter
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp asc
```

### 2. New .php files under web roots

```kql
DeviceFileEvents
| where Timestamp >= datetime($start)
| where ActionType == "FileCreated" and FileName endswith ".php"
| where FolderPath has_any ("/var/www/", "/srv/", "/usr/share/nginx/", "/public_html/", @"\inetpub\")
$kql_filter
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

### 3. Outbound connections from PHP workers

```kql
DeviceNetworkEvents
| where Timestamp >= datetime($start)
| where InitiatingProcessFileName has_any ("php-fpm", "php-cgi", "httpd", "apache2")
    or InitiatingProcessFileName matches regex @"^php[0-9.]*$$"
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
$kql_filter
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by FirstSeen asc
```

PHP applications that call outside APIs will show up here. Compare against what each application is expected to reach.
