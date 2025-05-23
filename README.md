
[![Malwatcher](/images/malwatcher_black.png)](https://github.com/R4z1xx/malwatcher)

[![GitHub Release](https://img.shields.io/github/v/release/R4z1xx/malwatcher)](https://github.com/R4z1xx/malwatcher/releases/latest)
[![Static Badge](https://img.shields.io/badge/Docker-ghcr.io-blue)](https://github.com/R4z1xx?tab=packages&repo_name=malwatcher)
[![GitHub License](https://img.shields.io/github/license/R4z1xx/malwatcher)](https://github.com/R4z1xx/malwatcher/blob/main/LICENSE)
[![Deploy Malwatcher images to ghcr.io](https://github.com/R4z1xx/malwatcher/actions/workflows/gchr_push_latest.yml/badge.svg)](https://github.com/R4z1xx/malwatcher/actions/workflows/gchr_push_latest.yml)

# What's this?
Malwatcher is a self-hosted platform that simplifies the process of verifying IOCs by combining multiple online tools into one interface, eliminating the need to visit each tool's website individually.

# Supported sources / APIs
| IPs Feed             | Domain Feed          | URL Feed             | File Feed                 |
| -------------------- | -------------------- | -------------------- | ------------------------  |
| VirusTotal           | VirusTotal           | VirusTotal           | VirusTotal                |
| AlienVault           | AlienVault           | AlienVault           | AlienVault                |
| DigitalSide          | DigitalSide          | DigitalSide          | DigitalSide               |
| Abuse.ch (UrlHaus)   | Abuse.ch (UrlHaus)   | Abuse.ch (UrlHaus)   | Abuse.ch (UrlHaus)        |
| Abuse.ch (ThreatFox) | Abuse.ch (ThreatFox) | Abuse.ch (ThreatFox) | Abuse.ch (ThreatFox)      |
|                      |                      |                      | *Abuse.ch (MalwareBazaar)*|
| InQuest IOCDB        | InQuest IOCDB        | InQuest IOCDB        | InQuest IOCDB             |
| InQuest RepDB        | InQuest RepDB        | InQuest RepDB        | InQuest RepDB             |
| InQuest DFI IOC      | InQuest DFI IOC      | InQuest DFI IOC      | InQuest DFI IOC           |
|                      |                      |                      | *InQuest DFI Hash*        |
| Tria.ge              | Tria.ge              |                      | Tria.ge                   |
|                      |                      | PolySwarm            | PolySwarm                 |
| *AbuseIPDB*          |                      |                      |                           |
| *BinaryDefense*      |                      |                      |                           |
| *IPSum*              |                      |                      |                           |

# Installation
### Prerequisites
- Docker - 19.03 or higher
- Docker Compose - 1.27.0 or higher
### Procedure
1. Clone the Malwatcher repo.
```bash
git clone https://github.com/R4z1xx/malwatcher.git
```
2. Go to malwatcher directory.
```bash
cd malwatcher
```
3. Edit logs folder permissions.
```bash
sudo chown 1001:1001 ./worker/logs
sudo chmod 700 ./worker/logs
```
3. Edit Malwatcher web interface port if necessary in the docker-compose file.
4. Edit modules config files with your API keys. Edit global settings in the config file.
5. Start Malwatcher docker stack
```bash
docker compose up -d
``` 

# Demo
Here is a preview of the Malwatcher web interface.<br>
/!\ The copy of defanged IOC on the report page only works if the web app is set to "https".

![Malwatcher Demo](/images/malwatcher-demo.gif)

# License
Malwatcher is released under GNU GPL-3.0. See [LICENSE](LICENSE)
