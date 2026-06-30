# Reporting & Responsible Disclosure Log

Every malicious indicator from this incident was reported to the relevant hosting, registrar,
browser/AV, and threat-intelligence services, plus law-enforcement channels. All indicators
below are **defanged**. Benign certificate-authority / OCSP / CDN endpoints contacted during
analysis were deliberately **excluded** (see `IOCs.md`).

| Destination | What was reported | Category | Status |
|---|---|---|---|
| **Cloudflare** (abuse) | `werknova[.]co`, `jarlontravon[.]com`, `block3[.]co`, `werknova[.]app` (filed separately — one host per report) | Phishing & Malware | Submitted ✓ |
| **Amazon Web Services** | Phishing email relayed through Amazon SES (`ap-northeast-1`) | Email / sending abuse | Submitted ✓ |
| **NICENIC** (registrar) | `block3[.]co` (+ `werknova[.]app`, already `clientHold`) | Registrar abuse | Emailed ✓ |
| **Namecheap** (registrar) | `werknova[.]co` | Registrar abuse | Emailed ✓ |
| **Google Safe Browsing** | `werknova[.]co/download` (malware), `block3[.]co` (social engineering), `jarlontravon[.]com` (malware) | Browser blocklist | Submitted ✓ |
| **Microsoft** (SmartScreen + Defender) | 3 URLs reported unsafe + sample `werknova_setup.msi` submitted | Unsafe site + sample | Submitted ✓ (sample analysis in progress) |
| **Cisco Talos** | `werknova_setup.msi` (file / web reputation) | Reputation dispute | Submitted ✓ (pending) |
| **abuse.ch — URLhaus** | `werknova[.]co/download` | Malware-delivery URL | Submitted ✓ |
| **abuse.ch — ThreatFox** | `jarlontravon[.]com` (domain), `104.21.33[.]210:443` (ip:port), dropper + payload SHA-256, campaign domains | C2 / payload IOCs | Submitted ✓ |
| **abuse.ch — MalwareBazaar** | `werknova_setup.msi` | Sample upload | Not completed (account upload rights unavailable; sample already on VirusTotal / Hybrid Analysis) |
| **Spamhaus** (Threat Intel Community) | `jarlontravon[.]com` | Scam / malware | Submitted ✓ |
| **.CO registry** (GoDaddy Registry) | `block3[.]co`, `werknova[.]co` | Registry escalation | Reserved — escalate only if registrar inaction after 5–10 business days |
| **LinkedIn** | Original job post / recruiter profile | Platform report | Optional / pending |
| **Real "block3"** (Nottingham, UK) | Brand-impersonation notice | Brand-owner notice | Optional / pending |
| **FBI IC3 + FTC** | Full incident (victim report) | Law enforcement / consumer protection | Recommended for personal protection |

**Notes**
- Malware family: **ACRStealer / Amatera** infostealer (Windows).
- The lure email **passed SPF, DKIM, and DMARC** via Amazon SES — the operator configured valid authentication on an attacker-controlled sending domain so the message reached inboxes. See `README.md`.
- Independent verdicts: VirusTotal and Hybrid Analysis both flagged the sample and the C2 as malicious.
