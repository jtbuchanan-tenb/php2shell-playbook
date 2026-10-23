## Elastic (ES|QL)

Behavior-based. No PHP2Shell IOCs have been published; these searches look for what exploitation does, not for known indicators.

These use Elastic Defend endpoint events with ECS field names. Check the index patterns and field names against your data before you trust an empty result.

### 1. A PHP worker starts a shell, curl or wget

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp >= TO_DATETIME("${start}T00:00:00Z")
    AND event.type == "start"
    AND (process.parent.name LIKE "php*" OR process.parent.name IN ("httpd", "apache2"))
    AND process.name IN ("sh", "bash", "dash", "zsh", "curl", "wget")
    $esql_filter
| KEEP @timestamp, host.name, user.name, process.parent.name, process.parent.command_line,
    process.name, process.command_line
| SORT @timestamp
```

### 2. New .php files under web roots

```esql
FROM logs-endpoint.events.file-*
| WHERE @timestamp >= TO_DATETIME("${start}T00:00:00Z")
    AND event.action == "creation"
    AND file.extension == "php"
    AND (file.path LIKE "/var/www/*" OR file.path LIKE "/srv/*"
         OR file.path LIKE "/usr/share/nginx/*" OR file.path LIKE "*/public_html/*")
    $esql_filter
| KEEP @timestamp, host.name, file.path, process.name, user.name
| SORT @timestamp
```

### 3. Outbound connections from PHP workers

```esql
FROM logs-endpoint.events.network-*
| WHERE @timestamp >= TO_DATETIME("${start}T00:00:00Z")
    AND network.direction == "egress"
    AND (process.name LIKE "php*" OR process.name IN ("httpd", "apache2"))
    AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
    $esql_filter
| STATS connections = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.name, process.name, destination.ip, destination.port
| SORT first_seen
```

PHP applications that call outside APIs will show up here. Compare against what each application is expected to reach.
