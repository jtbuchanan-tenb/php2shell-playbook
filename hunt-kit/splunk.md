## Splunk

Behavior-based. No PHP2Shell IOCs have been published; these searches look for what exploitation does, not for known indicators.

The first two searches use the CIM Endpoint data model. The third uses Sysmon for Linux network events, because the CIM network data model does not carry the process name. Check the field names against your data before you trust an empty result.

### 1. A PHP worker starts a shell, curl or wget

```spl
| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Processes.process) AS command_line
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("php*", "httpd", "apache2")
      Processes.process_name IN ("sh", "bash", "dash", "zsh", "curl", "wget")
      earliest="$start_spl" $proc_filter
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| convert ctime(first_seen) ctime(last_seen)
```

### 2. New .php files under web roots

```spl
| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen
    from datamodel=Endpoint.Filesystem
    where Filesystem.action="created" Filesystem.file_name="*.php"
      Filesystem.file_path IN ("/var/www/*", "/srv/*", "/usr/share/nginx/*", "*/public_html/*", "*\\inetpub\\*")
      earliest="$start_spl" $file_filter
    by Filesystem.dest Filesystem.file_path Filesystem.user
| convert ctime(first_seen) ctime(last_seen)
```

### 3. Outbound connections from PHP workers

```spl
sourcetype="sysmon:linux" EventCode=3 Initiated="true"
    Image IN ("*/php*", "*/httpd", "*/apache2")
    earliest="$start_spl" $net_filter
| where NOT (cidrmatch("10.0.0.0/8", DestinationIp) OR cidrmatch("172.16.0.0/12", DestinationIp)
    OR cidrmatch("192.168.0.0/16", DestinationIp) OR cidrmatch("127.0.0.0/8", DestinationIp))
| stats count min(_time) AS first_seen max(_time) AS last_seen by host Image DestinationIp DestinationPort
| convert ctime(first_seen) ctime(last_seen)
```

PHP applications that call outside APIs will show up here. Compare against what each application is expected to reach.
