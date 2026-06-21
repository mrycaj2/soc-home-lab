# SOC Home Lab - Splunk SIEM

## Środowisko
- Splunk Free (Docker) na serwerze Ubuntu 26.04
- Hardware: Lenovo YOGA, 7 GB RAM

## Co zrobiłem
- Skonfigurowałem Splunk w Dockerze i zaindeksowałem auth.log z systemu Linux
- Napisałem zapytania SPL do wykrywania nieudanych logowań SSH (brute-force)
- Grupowanie ataków po IP źródłowym z klasyfikacją poziomu ryzyka
- Skonfigurowałem alert odpalający się gdy jedno IP przekroczy 5 prób logowania

## Zapytanie SPL - detekcja brute-force
```splunk
index=main sourcetype="linux_secure" ("Failed password" OR "Invalid user")
| rex "for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts by src_ip, user
| sort -attempts
| eval risk=if(attempts>3,"HIGH","LOW")
```
## Zapytanie SPL - detekcja blokad Pi-Hole
```splunk
index=main sourcetype="pihole.log" "blocked"
| rex "blocked (?P<domain>[^\s]+)"
| stats count as blocked_count by domain
| sort -blocked_count
| head 10
```
