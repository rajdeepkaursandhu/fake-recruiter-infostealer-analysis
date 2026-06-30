# Where to report — takedown & blocklist guide

Goal: get `block3[.]co`, `werknova[.]co/.app`, and the C2 `jarlontravon[.]com` taken down, and get the URLs/hashes into the blocklists that protect everyone else. Ordered by leverage. Have your IOCs (`IOCs.md`) and a couple of screenshots ready for each.

---

## Tier 1 — fastest path to killing the infrastructure

**1. Cloudflare (highest leverage — fronts ALL of it)**
Both domains use Cloudflare nameservers, and the C2 IP `104.21.33[.]210` is a Cloudflare address. One abuse report can cover the whole campaign.
→ https://abuse.cloudflare.com/ — choose **Phishing** and **Malware**. List all three domains + the C2 IP.

**2. Amazon Web Services (the phishing emails were sent via Amazon SES)**
The `References` headers show `*.ap-northeast-1.amazonses.com`. AWS will act on SES abuse and can terminate the sending identity.
→ https://support.aws.amazon.com/#/contacts/report-abuse (or email `abuse@amazonaws.com`). Include the full email headers, the Message-ID, and the amazonses.com references.

**3. Domain registrars (abuse@)**
- `block3[.]co` → **NICENIC**: `abuse@nicenic.net`
- `werknova[.]co` → **NameCheap**: `abuse@namecheap.com` (and the form at https://support.namecheap.com → Abuse)
- `werknova[.]app` → look up its registrar via WHOIS, email that registrar's abuse address, and also notify **Google Registry** (operator of `.app`).

**4. .CO registry operator**
`.co` is operated by **.CO Internet S.A.S. (a GoDaddy Registry)** — they can act on `.co` abuse if a registrar is slow. Use their abuse/report channel.

---

## Tier 2 — global browser & AV blocklists (protect everyone, fast)

**5. Google Safe Browsing** (blocks in Chrome, Firefox, Safari)
→ https://safebrowsing.google.com/safebrowsing/report_phish/ — submit `werknova[.]co/download`, `block3[.]co`, and `jarlontravon[.]com`.

**6. Microsoft SmartScreen / Defender** (blocks in Edge + Windows)
- Report unsafe site: https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site
- Submit the **sample** for AV coverage: https://www.microsoft.com/en-us/wdsi/filesubmission
  (This also nudges Defender to actually detect the MSI it currently misses.)

**7. abuse.ch suite** (feeds firewalls, EDRs, DNS filters worldwide — free account via GitHub/LinkedIn/Google)
- **URLhaus** — the malware-delivery URL: `hxxps://werknova[.]co/download` → https://urlhaus.abuse.ch/
- **MalwareBazaar** — upload the actual sample you preserved (zip it, password `infected`) → https://bazaar.abuse.ch/
- **ThreatFox** — the C2 IOCs (`jarlontravon[.]com`, `104.21.33[.]210`, the hashes) → https://threatfox.abuse.ch/

**8. PhishTank (Cisco)** — community phishing DB feeding many products → https://phishtank.org/

**9. Netcraft** — performs active takedowns → https://report.netcraft.com/report

**10. Spamhaus** — report the domains/IPs (also partners with abuse.ch) → https://www.spamhaus.org/ (Threat Intel community submission).

**11. Your DNS filters** — you run AdGuard DNS + Trend Micro. Submit the domains to AdGuard's filter feedback and to community DNS blocklists (e.g. OISD / Hagezi accept submissions via their GitHub issues).

---

## Tier 3 — the platforms the lure rode in on

**12. LinkedIn** — you found the role via a LinkedIn listing, so report both:
- the **job posting** ("Report this job"), and
- the **company page** / recruiter profile ("Report").
This is important — it's the top of the funnel for the next victim.

**13. The real "block3" company (Nottingham, UK)** — notify them they're being impersonated. Brand owners often have legal/brand-protection takedown leverage you don't, and they'll want to know.

---

## Tier 4 — law enforcement & consumer protection (US — you're in TX)

**14. FBI IC3** — the primary US channel for internet crime → https://www.ic3.gov/ . File a complaint with the full timeline + IOCs.

**15. FTC** — fraud and (given the infostealer) identity-theft reporting:
- https://reportfraud.ftc.gov/
- https://www.identitytheft.gov/ (if you see any account misuse — it generates a recovery plan)

**16. (Optional) CISA** — https://www.cisa.gov/report

---

### Tips for effective reports
- Lead with the verdicts you already have (VirusTotal, Hybrid Analysis "malicious," LevelBlue "Phishing") — pre-corroborated reports get actioned faster.
- Attach 1–2 screenshots, not 20. The Trend Micro C2 block + a Hybrid Analysis verdict is plenty.
- Submit the **defanged** IOCs from `IOCs.md`, and **exclude** the Certum/Microsoft/DigiCert noise listed there.
- Keep a simple log (date, where reported, ticket #) — it's good evidence and good practice.
