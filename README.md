
[![Malwatcher](/images/malwatcher_black.png)](https://github.com/R4z1xx/malwatcher)

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
| InQuest IOCDB*       | InQuest IOCDB*       | InQuest IOCDB*       | InQuest IOCDB*            |
| InQuest RepDB*       | InQuest RepDB*       | InQuest RepDB*       | InQuest RepDB*            |
| InQuest DFI IOC*     | InQuest DFI IOC*     | InQuest DFI IOC*     | InQuest DFI IOC*          |
|                      |                      |                      | *InQuest DFI Hash*        |
| Tria.ge*             | Tria.ge*             |                      | Tria.ge*                  |
|                      |                      | PolySwarm*           | PolySwarm*                |
| *AbuseIPDB*          |                      |                      |                           |
| *BinaryDefense*      |                      |                      |                           |
| *IPSum*              |                      |                      |                           |

*\*new API sources*

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
3. Edit Malwatcher web interface port if necessary in the docker-compose file.
4. Start Malwatcher docker stack
```bash
docker compose up -d
``` 

# Demo
Here is a preview of the Malwatcher web interface.<br>
/!\ The copy of defanged IOC on the report page only works if the web app is set to "https".

![Malwatcher Demo](/images/malwatcher-demo.gif)

# License
Malwatcher is released under GNU GPL-3.0. See [LICENSE](LICENSE)
