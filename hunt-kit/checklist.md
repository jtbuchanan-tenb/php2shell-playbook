## Manual checklist for one Linux host

Behavior-based. No PHP2Shell IOCs have been published; these checks look for what exploitation does, not for known indicators.

Use this on a host with no EDR, or to confirm a hit from the searches above. It covers the same three behaviors. Run the commands as root, and adjust the web root paths to the host.

1. **Shells under PHP workers right now.** Look for `sh`, `bash`, `dash`, `curl` or `wget` running as a child of `php-fpm`, `php-cgi`, `httpd` or `apache2`:

   ```bash
   ps -eo pid,ppid,user,lstart,cmd --forest | grep -B2 -A3 -E 'php-fpm|php-cgi|httpd|apache2'
   ```

2. **Shells under PHP workers in the past.** If auditd records `execve`, search from the hunt start for executions whose parent is a PHP worker:

   ```bash
   ausearch -sc execve -ts $start_us -i | grep -E 'ppid=|exe=' | less
   ```

   `-ts` reads the date in the host's locale format. `$start_us` is the US format; change it if the host uses another.

3. **New .php files under web roots** since $start:

   ```bash
   find /var/www /srv /usr/share/nginx /home/*/public_html -name '*.php' -newermt $start -ls 2>/dev/null
   ```

   Look hard at files with random names, files in upload or cache folders, and files owned by the PHP worker's user.

4. **Outbound connections from PHP workers** right now:

   ```bash
   ss -tnp state established | grep -E 'php-fpm|php-cgi|httpd|apache2'
   ```

5. **Anything you find:** keep the host as it is, copy the file and its timestamps, and hand it to incident response before you clean up.
