# SOC Home Lab – Splunk SIEM

## Environment
Splunk Free running in Docker on a dedicated Ubuntu 26.04 server (Lenovo YOGA, 8 GB RAM).

## What I built

Ingested two log sources into Splunk: Linux auth.log and DNS logs from Pi-hole.

On auth.log I wrote an SPL query to detect failed SSH logins. It groups attempts by source IP and username and classifies risk as HIGH when a single IP exceeds 3 failed attempts. Configured an alert that fires automatically when the threshold of 5 attempts is crossed.

On Pi-hole DNS logs I analyze network DNS traffic. I extract blocked domains and sort by attempt count. During analysis I detected a device on the network repeatedly querying a domain on Pi-hole's blocklist and traced it back to a specific IP address.

## SPL – SSH Brute-Force Detection
```splunk
index=main sourcetype="linux_secure" ("Failed password" OR "Invalid user")
| rex "for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts by src_ip, user
| sort -attempts
| eval risk=if(attempts>3,"HIGH","LOW")
```

## SPL – Pi-hole DNS Analysis
```splunk
index=main sourcetype="pihole.log" "blocked"
| rex "blocked (?P<domain>[^\s]+)"
| stats count as blocked_count by domain
| sort -blocked_count
| head 10
```

## Stack
Splunk · SPL · Docker · Linux · SSH · Pi-hole · auth.log · DNS logs

## Screenshots
### SSH Brute-Force Detection
![SSH Brute-Force Detection](screenshots/splunk_ssh_bruteforce_detection.png)
### DNS Blocked Domains
![DNS Blocked Domains](screenshots/splunk_dns_blocked_domains.png)
