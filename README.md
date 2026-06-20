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
index=main sourcetype="linux_secure" "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts by src_ip
| where attempts > 5
| eval risk="HIGH"
