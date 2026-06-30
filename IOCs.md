# Indicators of Compromise — Block3 / Werknova ACRStealer campaign

All indicators are **defanged**. Re-fang only inside isolated analysis environments.
Campaign: fake Web3 recruiting → rogue "meeting app" → ACRStealer infostealer.
Last updated: 2026-06-28. (email-auth finding corrected: message PASSED SPF/DKIM/DMARC via Amazon SES)

---

## Domains

```
block3[.]co            # fake company / phishing (impersonates a real "block3" brand)
werknova[.]co          # rogue "meeting app" + malware delivery
werknova[.]app         # booking/calendar lure (observed dead at time of write-up)
jarlontravon[.]com     # command-and-control (C2)
```

## URLs

```
hxxps://werknova[.]co/download                       # MSI delivery, access-code gated
hxxps://werknova[.]app/calendar/<uuid>               # fake booking link
hxxps://werknova[.]co/meet/<uuid>/<code>             # fake meeting room
hxxp://jarlontravon[.]com/                           # C2
```

## IP addresses

```
104.21.33[.]210        # C2 (jarlontravon[.]com), Cloudflare-fronted
217.20.50[.]151        # secondary, flagged + blocked by Bitdefender (AS20253)
217.20.50[.]153        # secondary, flagged + blocked by Bitdefender (AS20253)
```

## Files / hashes

```
Filename:  werknova_setup.msi  (alias: kollabit_setup.msi)
SHA-256:   d59d3443120c77b1cf524a1926074dccbe9fa0ce2054f4b7962ec1301b8ca4c5   # dropper (MSI)
SHA-256:   6671e91ed4e3e51601f256150f94585f551978a34199dcea665a5328a3f576aa   # payload DLL (ACRStealer)
Loader:    draw.io.exe  (legitimate binary abused for DLL search-order hijacking)
```

## Email / sender

```
emma.martin@block3[.]co            # display sender
Relay:   *.ap-northeast-1.amazonses.com   # sent via Amazon SES (Tokyo)
Auth:    SPF=pass (23.251.234[.]58) / DKIM=pass (block3[.]co + amazonses[.]com) / DMARC=bestguesspass; plain-text body
Subjects observed:
  - "Re: Thanks for applying for the Web3 Strategy Analyst at Block3"
  - "Second Opportunity to Connect – Web3 Strategy Analyst at Block3"
Persona / role lure:  "Emma Martin" — recruiter, "Web3 Strategy Analyst"
Access / room code:   YU-FPHR-FMN6
```

## Malware family

```
Infostealer / ACRStealer  (MaaS; GrMsk / "Amatera" lineage)
Capabilities: browser credentials & cookies, autofill, crypto wallets,
              FTP/remote-access creds, email/messaging app data,
              password-manager files, VPN credentials.
TTPs: Dead Drop Resolver (DDR) C2 via legitimate services; DLL sideloading;
      MSI bloat for sandbox evasion; (recent builds) TLS C2 + syscall evasion.
```

## Registration metadata

```
block3[.]co     created 2026-04-30  registrar NICENIC INTERNATIONAL GROUP  abuse@nicenic.net
werknova[.]co   created 2026-06-09  registrar NameCheap, Inc.              abuse@namecheap.com
Both:           NS = BRYNNE.NS.CLOUDFLARE.COM / KOBE.NS.CLOUDFLARE.COM ; DNSSEC unsigned
```

---

## NOT malicious — explicitly excluded (do not report)

These were contacted during analysis but are **legitimate certificate-authority / OCSP infrastructure**
(normal Authenticode / certificate-revocation traffic). Reporting them would generate false positives:

```
repository.certum[.]pl
subca.ocsp-certum[.]com
*.ocsp-certum[.]com
cevcsca2021.ocsp-certum[.]com
ocsp-certum[.]com
edge.ds-c7110-microsoft.global.dns.qwilted-cds.cqloud[.]com   # Microsoft/Edge CDN noise
eip-terr-na.cdp1.digicert.com.akahost[.]net                   # DigiCert CRL/OCSP
nexusrules.officeapps.live[.]com                              # Microsoft Office service
```
