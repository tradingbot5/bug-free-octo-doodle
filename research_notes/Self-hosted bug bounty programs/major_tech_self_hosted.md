# Self-Hosted Bug Bounty Programs: Major Tech Companies

## Does Google run its own bug bounty separate from HackerOne?

### Takeaway
Yes. Google runs its Vulnerability Reward Program (VRP) entirely on its own platform at bughunters.google.com, which is fully self-hosted by Google/Alphabet — it does not use HackerOne, Bugcrowd, or any other third-party bounty platform. In 2025, Google paid out over $17 million to researchers globally.

### Cited Findings
- Google's VRP is hosted at bughunters.google.com, Google's proprietary bug bounty platform — [Google Bug Hunters](https://bughunters.google.com/about/rules)
- Google paid out over $17 million in VRP rewards in 2025, its 15th anniversary year — [SecurityWeek](https://www.securityweek.com/google-paid-out-17-million-in-bug-bounty-rewards-in-2025/)
- In 2024, Google paid out $11.8 million to 660 researchers; its largest single payout was $110,000 — [Google Security Blog](https://security.googleblog.com/2025/03/vulnerability-reward-program-2024-in.html)
- Google revamped Android and Chrome rewards: the top Android zero-click Titan M exploit with persistence now pays $1.5 million (up from $1 million); Chrome base rewards fell in most categories — [SecurityWeek](https://www.securityweek.com/google-adjusts-bug-bounties-chrome-payouts-drop-as-android-rewards-rise-amid-ai-surge/)
- Mobile VRP covers three tiers of apps; Tier 1 is limited to Google Play Services, AGSA, Google Cloud, and Gmail — [Google Mobile VRP Rules](https://bughunters.google.com/about/rules/android-friends/6618732618186752/google-mobile-vulnerability-reward-program-rules)
- Chrome VRP historically paid up to $250,000; post-overhaul, some Chrome bug rewards are reported to be 10 times smaller — [Security Affairs](https://securityaffairs.com/191600/security/google-revamps-bug-bounty-programs-android-rewards-rise-chrome-payouts-drop-in-the-age-of-ai.html)
- Cloud VRP top tier: up to $151,515 — [TechRadar](https://www.techradar.com/pro/security/google-bug-bounty-payments-hit-nearly-usd12-million-in-2024)
- Google runs bonus programs as additional percentage on top of normal rewards, applied at the discretion of the reward panel — [Google Bonus Awards Rules](https://bughunters.google.com/about/rules/5429687846305792/bonus-awards-rules)

### Inferences
- Google's bughunters.google.com is one of the most mature self-hosted platforms in the industry; its scale ($17M/year) suggests significant internal investment in the platform.
- The shift toward higher Android rewards and lower Chrome rewards likely reflects Google's strategic security focus on mobile as a higher-value attack surface.

### Gaps
- Exact 2025/2026 per-severity payout tables for each sub-program (Android, Chrome, Web, Cloud) could not be confirmed from secondary sources; bughunters.google.com renders rule tables dynamically and WebFetch returned only page titles.


## Does Apple have its own security research program?

### Takeaway
Yes. Apple runs a fully self-hosted Security Bounty program at security.apple.com/security-bounty, with submissions via security.apple.com/submit. In October 2025, Apple announced a major overhaul doubling the top payout to $2 million (with bonuses potentially exceeding $5 million) — the highest top reward in the industry.

### Cited Findings
- Apple's program is self-hosted at security.apple.com; submission page is at security.apple.com/submit — [Apple Security Research Blog](https://security.apple.com/blog/apple-security-bounty-evolved/)
- Revised program takes effect November 2025; until then, reports are judged under both old and new frameworks and the higher award is paid — [Apple Security Research Blog](https://security.apple.com/blog/apple-security-bounty-evolved/)
- New top payout tiers: zero-click remote attack chain → $2 million (up from $1 million); one-click remote chain → $1 million (up from $250,000); wireless proximity attack → $1 million (up from $250,000); physical device access (locked) → $500,000 (up from $250,000); app sandbox escape to SPTM bypass → $500,000 (up from $150,000) — [Apple Security Research Blog](https://security.apple.com/blog/apple-security-bounty-evolved/)
- Additional specific tiers: broad unauthorized iCloud access → $1 million; WebKit one-click sandbox escape → up to $300,000; WebKit chain to unsigned code with arbitrary entitlements → $1 million; low-impact reports → $1,000 floor — [Apple Security Research Blog](https://security.apple.com/blog/apple-security-bounty-evolved/)
- Bonuses for beta-software issues and Lockdown Mode bypasses can push a combined payout above $5 million — [Apple Security Research Blog](https://security.apple.com/blog/apple-security-bounty-evolved/)
- "Target Flags" allow accelerated awards, paid after Apple verifies the report even before a fix ships — [Apple Security Research Blog](https://security.apple.com/blog/apple-security-bounty-evolved/)
- Covered platforms: iOS, iPadOS, macOS, visionOS, watchOS, and tvOS — [Apple Security Research Blog](https://security.apple.com/blog/apple-security-bounty-evolved/)
- Security Research Device (SRD) program for 2026 closes applications October 31, 2025, open to researchers with proven track records — [Apple Security Research Blog](https://security.apple.com/blog/apple-security-bounty-evolved/)
- Official payout category page is hosted at security.apple.com/bounty/categories — [Apple Security Bounty Categories](https://security.apple.com/bounty/categories)

### Inferences
- Apple's $2M top payout (with $5M+ bonus potential) makes it arguably the most lucrative self-hosted program for mobile/OS research.
- The "Target Flags" mechanism is a notable innovation — paying researchers before a fix ships, which incentivizes high-quality exploit-level research.

### Gaps
- Whether the program requires an invitation or is open to all researchers was not definitively confirmed; the SRD program requires application but the general bounty appears open to all.


## Does Microsoft run independent programs beyond HackerOne?

### Takeaway
Yes. Microsoft runs all its bug bounty programs directly through msrc.microsoft.com/bounty (Microsoft Security Response Center), which is a self-hosted portal. Reports go directly to Microsoft, not through HackerOne or Bugcrowd.

### Cited Findings
- Microsoft's bounty programs are listed and submitted at msrc.microsoft.com — [Microsoft Bug Bounty Program](https://microsoft.com/msrc/bounty)
- Three main program categories: Cloud Programs (up to $100,000), Endpoint & On-Prem Programs (up to $250,000), and Zero Day Quest (up to $100,000) — [Microsoft Bug Bounty](https://microsoft.com/en-us/msrc/bounty)
- Microsoft's headline figure: "Earn up to $250,000 USD in bug bounty awards" — [Microsoft Bug Bounty](https://microsoft.com/en-us/msrc/bounty)
- No third-party platform (HackerOne, Bugcrowd) mentioned on the bounty page; submission link goes to msrc.microsoft.com — [Microsoft Bug Bounty](https://microsoft.com/en-us/msrc/bounty)
- In the period July 2025 to June 2026 Microsoft paid out over $20 million in bounties to 562 researchers; the largest single payout was $200,000 — [SecurityWeek](https://www.securityweek.com/microsoft-bug-bounty-program-20-million-paid-to-500-researchers/)
- "In Scope By Default" policy, in force since December 2025, means vulnerabilities in areas not covered by a specific program still earn rewards based on severity — [SecurityWeek](https://www.securityweek.com/microsoft-will-expand-bug-bounties-even-on-programs-without-official-payouts/)
- Zero Day Quest hacking contest contributed $2.3 million of the total payouts — [SecurityWeek](https://www.securityweek.com/microsoft-bug-bounty-program-20-million-paid-to-500-researchers/)
- Older historical range (may be outdated): $500 to $250,000 USD; Mitigation Bypass and Bounty for Defense program: up to $100,000 (plus up to an additional $100,000) — [Windows Central](https://windowscentral.com/microsoft-launches-windows-bug-bounty-program-payouts-250000)

### Inferences
- Microsoft's "In Scope By Default" policy is a significant shift that provides clarity for researchers — any Microsoft-owned vulnerability now has a potential payout path.
- Azure and Microsoft 365 are covered under the Cloud Programs category, so GCP/Azure separation from HackerOne is handled entirely through MSRC.

### Gaps
- Specific per-severity payout tables for each sub-program (Cloud, Endpoint, Zero Day Quest) were not available from the fetch results.


## Does Meta/Facebook run its own program?

### Takeaway
Yes. Meta runs its bug bounty program on its own portal at bugbounty.meta.com, submitted via bugbounty.meta.com/report. While Meta uses Bugcrowd and HackerOne for payment processing, all submissions go through Meta's own portal.

### Cited Findings
- Submissions go through Meta's own portal at bugbounty.meta.com/report; Meta explicitly says not to contact staff or use other channels — [Meta Bug Bounty Scope](https://bugbounty.meta.com/scope/)
- Meta may share severity, payout, and (with consent) researcher identity with Bugcrowd and HackerOne for payment processing only — submission itself is self-hosted — [Meta Bug Bounty Scope](https://bugbounty.meta.com/scope/)
- Minimum bounty: $500; rewards are impact-based, not flat-rate — [Meta Bug Bounty Scope](https://bugbounty.meta.com/scope/)
- Top reward for WhatsApp Private Processing: up to $300,000 USD (invitation-only scope) — [Meta Bug Bounty Scope](https://bugbounty.meta.com/scope/)
- Scope includes: Facebook (facebook.com, fb.com), WhatsApp (web.whatsapp.com), Instagram (instagram.com, threads.com), Messenger (messenger.com), Meta AI (meta.ai), Meta Quest (hardware + apps), Ray-Ban Meta smart glasses, and Meta's open-source GitHub organizations (facebook, facebookincubator) — [Meta Bug Bounty Scope](https://bugbounty.meta.com/scope/)
- Meta has paid $14 million in bounties since inception with over 150,000 reports received — [TechZine](https://www.techzine.eu/news/privacy-compliance/69870/meta-platforms-inc-expands-its-bug-bounty-program/)
- Meta extended scope to include AI/LLM vulnerabilities and data scraping — the first bug bounty program to offer coverage for data scraping — [TechZine](https://www.techzine.eu/news/privacy-compliance/69870/meta-platforms-inc-expands-its-bug-bounty-program/)
- Out of scope: spam, denial-of-service, most content injection issues, non-Meta hardware and software — [Meta Bug Bounty Scope](https://bugbounty.meta.com/scope/)

### Inferences
- Meta's hybrid approach (self-hosted portal + third-party payment processors) is a practical model that keeps program control in-house while using established payment rails.

### Gaps
- Full payout table by vulnerability severity/type was not visible; the official scope page states rewards are discretionary based on risk, impact, and user count without publishing a formal tier table.


## Samsung, Intel, AMD, Qualcomm — direct programs?

### Takeaway
Samsung runs a self-hosted program at security.samsung.com with up to $1 million for critical scenarios. Intel suspended financial rewards and moved to Intigriti (not self-hosted, no pay). AMD runs on Intigriti (not self-hosted). Qualcomm runs on HackerOne (not self-hosted).

### Cited Findings

**Samsung:**
- Samsung's Mobile Security Rewards Program is accessible at security.samsung.com (domain was unreachable at time of research) — [TechRadar](https://www.techradar.com/pro/samsung-is-offering-up-to-dollar1-million-to-anyone-who-can-find-security-flaws-in-its-software)
- Samsung has paid out nearly $5 million in total since its 2017 launch, including $828,000 to 113 researchers in 2023 — [SecurityWeek](https://www.securityweek.com/samsung-bug-bounty-program-payouts-reach-5m-top-reward-increased-to-1m/)
- In late 2024, Samsung raised the maximum reward to $1 million under the new Important Scenario Vulnerability Programme for high-impact attack scenarios — [Samsung News](https://news.samsung.com/sg/samsung-electronics-scales-up-mobile-security-rewards-programme-to-boost-industry-collaboration-and-safety)
- Reward tiers under Important Scenario: remote code execution → $1,000,000; local arbitrary execution → ~$300,000 — [TechRadar](https://www.techradar.com/pro/samsung-is-offering-up-to-dollar1-million-to-anyone-who-can-find-security-flaws-in-its-software)
- Maximum rewards require a buildable, persistent, zero-click exploit on Samsung's main Galaxy device models running the latest security update — [TechRadar](https://www.techradar.com/pro/samsung-is-offering-up-to-dollar1-million-to-anyone-who-can-find-security-flaws-in-its-software)
- Original program scope covered 38 Samsung mobile devices from 2016 onwards receiving regular security updates, plus Samsung services and apps — [Graham Cluley](https://grahamcluley.com/samsung-bug-bounty/)
- Base payout starts at $200 for low-severity findings — [Graham Cluley](https://grahamcluley.com/samsung-bug-bounty/)

**Intel:**
- Intel suspended its bug bounty program (which had paid up to $100,000 per finding) and moved to a no-reward vulnerability disclosure model on Intigriti — [Tweaktown](https://www.tweaktown.com/news/113651/intel-kills-its-bug-bounty-program-that-paid-up-to-100-000-for-flagging-security-vulnerabilities/index.html)
- The suspension occurred after Intel evaluated its program in January 2026 and cited a flood of AI-assisted, high-volume vulnerability reports — [Notebookcheck](https://www.notebookcheck.com/Intel-stoppt-vorerst-sein-100-000-Dollar-Bug-Bounty-Programm.1403875.0.html)
- Intel's original program ran on HackerOne (not self-hosted); payout tiers were Tier 1: $2,000–$100,000; Tier 2: $1,000–$30,000; Tier 3: $500–$10,000; Tier 4: $250–$5,000 — [TechTarget](https://www.techtarget.com/searchsecurity/news/252435175/Intel-bug-bounty-programs-widened-after-Meltdown-and-Spectre)

**AMD:**
- AMD runs its bounty program through Intigriti (NOT self-hosted) — [Intigriti](https://app.intigriti.com/programs/amd/amd/detail)
- AMD payout tiers: software bugs $500 (low) to $10,000 (critical); firmware $1,000 to $15,000; hardware $2,000 to $30,000 — [TechRadar](https://www.techradar.com/pro/security/amd-launches-bug-bounty-program-with-some-seriously-big-rewards)
- Controversy in 2026: AMD denied a $10,000 bounty for a critical auto-updater RCE vulnerability (CVE-2026-40677, CVSS 7.7) by reclassifying it as optional software outside core product scope; AMD subsequently updated its disclosure rules requiring written permission before public disclosure — [SC World](https://www.scworld.com/brief/amd-faces-backlash-over-denied-bug-bounty-and-changed-disclosure-rules)

**Qualcomm:**
- Qualcomm's program runs on HackerOne (NOT self-hosted) — [Tom's Hardware](https://www.tomshardware.com/uk/news/qualcomm-bug-bounty-program-hackerone,33048.html)
- Maximum reward was $15,000 at launch in 2016; the program started as invitation-only — [FoneArena](https://www.fonearena.com/blog/203967/qualcomm-launches-bug-bounty-program-to-offer-rewards-up-to-15000.html/)
- Top-tier reward for cellular modem critical vulnerabilities: $15,000 — [TelecomTV](https://telecomtv.com/content/tracker/qualcomm-announces-launch-of-bounty-program-offering-up-to-15-000-usd-for-the-discovery-of-vulnerabilities-24465)
- No 2025 program updates found; current status unconfirmed

### Inferences
- Only Samsung among the four chip/hardware vendors has a clearly self-hosted, high-value program (up to $1M).
- Intel's suspension and AMD's disclosure controversy suggest hardware vendors face specific challenges with vulnerability research programs, including AI-generated volume and disputes over scope classification.

### Gaps
- Current status of Samsung's portal (security.samsung.com was unreachable during research); exact current scope and payout table not confirmed from primary source.
- Qualcomm's current 2025/2026 payout table and program status not confirmed.
- AMD's Intigriti program launch date is unclear.


## Do major browser vendors (Mozilla, Brave) run direct programs?

### Takeaway
Mozilla runs a fully self-hosted bug bounty program via its own Bugzilla bug tracker at bugzilla.mozilla.org. Brave's own program could not be confirmed from available sources.

### Cited Findings

**Mozilla:**
- Mozilla's Client Bug Bounty program is self-hosted; submissions go through Mozilla's own Bugzilla tracker at bugzilla.mozilla.org using a specific client bug bounty form — [Mozilla Client Bug Bounty](https://www.mozilla.org/en-US/security/client-bug-bounty/)
- Payout tiers: sandbox escapes and WebExtension install prompt bypasses → up to $20,000; UXSS (cross-origin script execution) → up to $10,000; sec-high issues, GPU memory corruption, parent process info disclosure → up to $3,000 — [Mozilla Client Bug Bounty](https://www.mozilla.org/en-US/security/client-bug-bounty/)
- Exploit mitigation bypasses earn 50% bonus on top of the regular vulnerability payout when shown without privileged access — [Mozilla Client Bug Bounty](https://www.mozilla.org/en-US/security/client-bug-bounty/)
- Scope: Firefox, Firefox for Android, Firefox for iOS (main development and released versions including Nightly, Beta, and release) — [Mozilla Client Bug Bounty](https://www.mozilla.org/en-US/security/client-bug-bounty/)
- Mozilla has paid over $4 million across all its bounty programs combined — [Mozilla Firefox Bug Bounty Hall of Fame](https://www.mozilla.org/security/bug-bounty/hall-of-fame)
- End-of-life products, unbundled third-party software (extensions, binary plugins), and the older Fennec Android app are excluded — [Mozilla Client Bug Bounty](https://www.mozilla.org/en-US/security/client-bug-bounty/)
- Mozilla also runs a Web and Services Bug Bounty for mozilla.org-hosted services — [Mozilla Web Bug Bounty](https://www.mozilla.org/en-US/security/web-bug-bounty/)

**Brave:**
- No confirmed information found about Brave Software's own bug bounty program; Brave staff appear in Mozilla's Firefox bug bounty hall of fame as reporters, not hosts — [Mozilla Firefox Bug Bounty Hall of Fame](https://www.mozilla.org/security/bug-bounty/hall-of-fame)

### Inferences
- Mozilla's use of Bugzilla as its bounty submission system is unique among major vendors and reflects its open-source heritage; researchers need a free Bugzilla account rather than a bug bounty platform account.

### Gaps
- Brave's own security vulnerability program: no confirmed sources found; it may use HackerOne or direct email; check brave.com/security for current details.
- Moderate-severity Mozilla payout ranges: older sources cited $500–$2,000 but this predates 2025 and may be outdated.


## Cloud providers (AWS, Azure, GCP) — independent programs or HackerOne?

### Takeaway
Google Cloud (GCP) is covered under Google's self-hosted VRP at bughunters.google.com. Microsoft Azure is covered under Microsoft's self-hosted MSRC at msrc.microsoft.com. AWS launched its first dedicated bug bounty program in 2024 via HackerOne (not self-hosted).

### Cited Findings
- AWS launched its first dedicated bug bounty program in September 2024, hosted on HackerOne (NOT self-hosted); coverage includes EC2 and RDS — [DutchITChannel](https://www.dutchitchannel.nl/news/507281/aws-lanceert-bugbountyprogramma)
- Prior to 2024, AWS did not offer a bug bounty program — [Cloudonaut (2020)](https://cloudonaut.io/aws-needs-a-bug-bounty-program)
- Google Cloud VRP top payout: up to $151,515; hosted at bughunters.google.com — [TechRadar](https://www.techradar.com/pro/security/google-bug-bounty-payments-hit-nearly-usd12-million-in-2024)
- Microsoft Azure is covered under Microsoft's Cloud Programs at msrc.microsoft.com, paying up to $100,000 — [Microsoft Bug Bounty](https://microsoft.com/en-us/msrc/bounty)

### Inferences
- Among the three major cloud providers, only Google Cloud (via Google VRP) and Azure (via MSRC) are genuinely self-hosted. AWS uses a third-party platform (HackerOne).

### Gaps
- Exact AWS HackerOne payout amounts not found; check the HackerOne program page for current AWS bounty terms.


## Notable programs from Asian tech companies (Alibaba, Baidu, Tencent, Samsung)

### Takeaway
Tencent runs a self-hosted TSRC program at en.security.tencent.com covering all major Tencent products. Alibaba operates a partially self-hosted program at security.alibaba.com (ASRC) but also uses HackerOne. Samsung's self-hosted program is covered under the Samsung section above. No confirmed information found for Baidu's program.

### Cited Findings

**Tencent TSRC (Security Response Center):**
- Fully self-hosted at en.security.tencent.com; submissions go through the site's "Submit Report" page — [Tencent TSRC Policy](https://en.security.tencent.com/policy)
- Scope: WeChat, WeCom, QQ, Tencent Yuanbao, Tencent Pay and wallet services, Tencent Video, King of Glory, Game for Peace, Voov Meeting, Tencent Cloud (platform and owned IPs only), PC/Mobile Manager, and most other Tencent mobile/web products — [Tencent TSRC Policy](https://en.security.tencent.com/policy)
- Rewards paid in USD; exact payout amounts not stated in text (displayed as images on the page) — [Tencent TSRC Policy](https://en.security.tencent.com/policy)
- Historical reports: Tencent's top award cited at $15,000 in older coverage — [Threatpost](https://threatpost.com/tencent-top-bug-bounty-award-15k/154816)
- Although Tencent has a HackerOne partnership, the self-hosted TSRC uses its own platform; rewards are decided exclusively by Tencent — [SecurityWeek](https://www.securityweek.com/tencent-partners-hackerone-bug-bounty-program/)
- Eligibility: must be 13+, not a Tencent employee, not a sanctioned person, and must be the first reporter — [Tencent TSRC Policy](https://en.security.tencent.com/policy)
- Out of scope: self-XSS, clickjacking, missing cookie flags, flooding, informational leaks that can't enable attacks — [Tencent TSRC Policy](https://en.security.tencent.com/policy)
- Overseas payments use a third-party payment provider and take longer — [Tencent TSRC Policy](https://en.security.tencent.com/policy)

**Alibaba:**
- Alibaba runs a self-managed bug bounty on its own ASRC (Alibaba Security Response Center) at security.alibaba.com, separate from HackerOne — [HackerOne Alibaba Policy](https://hackerone.com/alibaba/policy_versions)
- Alibaba also has a presence on HackerOne for international researchers; HackerOne policy references the ASRC platform for other assets — [HackerOne Alibaba Policy](https://hackerone.com/alibaba/policy_versions)
- An Alibaba Security meetup in 2025 listed both ASRC private bug bounty program and ASRC Vulnerability Rewards Program as active — [SecurityWeek Lazada](https://www.securityweek.com/alibabas-lazada-launches-public-bug-bounty-program/)
- Alibaba's Lazada subsidiary runs a separate public program on YesWeHack — [YesWeHack](https://yeswehack.com/programs/ant-group-security-response-center-bug-bounty-program)

**Baidu:**
- No confirmed information found for Baidu's bug bounty program from available sources.

### Inferences
- Tencent's self-hosted TSRC appears to be the most robust independent Asian tech company bug bounty program, covering a wide product surface.
- Alibaba's split approach (self-hosted ASRC + HackerOne) is similar to Meta's model — using third-party platforms for specific functions while maintaining a proprietary portal.

### Gaps
- Exact Tencent TSRC payout amounts could not be confirmed (displayed as images, not text on the policy page).
- Baidu: no program found in available sources; may operate internally or not have a public program.
- Current Alibaba ASRC payout table and scope details not confirmed from primary sources.
- Samsung's self-hosted portal (security.samsung.com) was unreachable at time of research; payout details sourced from news coverage only.
