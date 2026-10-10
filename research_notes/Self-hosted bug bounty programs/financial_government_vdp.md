# Bug Bounty and VDP Programs: Financial Institutions and Government Agencies

## Major Banks — Bug Bounty and VDP Programs

### Takeaway
A 2024 Wavestone benchmark found only 26% of the world's top 100 banks had a VDP and only 5% ran a public paid bug bounty; most banks that do have programs use managed platforms (HackerOne, Bugcrowd, Synack) rather than fully self-hosting. JPMorgan Chase is a notable exception with a semi-self-hosted disclosure portal powered by Synack.

### Cited Findings

- **Industry adoption (top 100 banks, Q3 2023):** 34% had at least one active Vulnerability Report Channel (VRC), 26% had a VDP, and only 5% ran a public Bug Bounty Program. North American banks had 72% VRC adoption vs. 49% in Europe. In Asia/South America (43 banks), only one bank had a VDP. — [Wavestone RiskInsight Benchmark 2024](https://www.riskinsight-wavestone.com/en/2024/02/bug-bounty-insight-and-benchmark-on-the-banking-and-public-sectors-2024/)
- **Netherlands:** Reached 100% VRC/VDP adoption among its top banks. — [Wavestone RiskInsight Benchmark 2024](https://www.riskinsight-wavestone.com/en/2024/02/bug-bounty-insight-and-benchmark-on-the-banking-and-public-sectors-2024/)
- **Platform preference:** Most banks built in-house (self-hosted) programs; those using platforms favored BugCrowd, Synack, and HackerOne — no specific bank-to-platform mapping is provided in the benchmark. — [Wavestone RiskInsight Benchmark 2024](https://www.riskinsight-wavestone.com/en/2024/02/bug-bounty-insight-and-benchmark-on-the-banking-and-public-sectors-2024/)

**JPMorgan Chase**
- Runs a "Responsible Disclosure Program" accessible at `chase.com/digital/resources/privacy-security/security/vulnerability-disclosure` — linked out to a Synack-powered portal at `responsibledisclosure.jpmorganchase.com`. — [JPMorgan Chase Responsible Disclosure](https://www.chase.com/digital/resources/privacy-security/security/vulnerability-disclosure)
- The bank's portal is described as "managed by our third party vendor" (Synack). It is not fully self-hosted. Payout and scope details are behind a separate vendor-managed login. — [JPMC Responsible Disclosure – Synack](https://responsibledisclosure.jpmorganchase.com/hc/en-us)
- No public bounty rewards mentioned on the consumer-facing page; this appears to be a VDP (no pay). — [JPMorgan Chase Responsible Disclosure](https://www.chase.com/digital/resources/privacy-security/security/vulnerability-disclosure)
- American Banker noted JPMorgan "invites white-hat hackers to security team," and researchers who follow guidelines will not face legal repercussions if they do not use findings to commit fraud. — [American Banker](https://www.americanbanker.com/news/jpmorgan-invites-white-hat-hackers-to-security-team)

**Goldman Sachs**
- Runs a bug bounty program through **HackerOne** at `hackerone.com/goldmansachs`. Submissions should include detailed reports with reproducible steps. — [Goldman Sachs on HackerOne](https://hackerone.com/goldmansachs)
- FireBounty also lists Goldman Sachs's VDP. — [FireBounty Goldman Sachs VDP](https://firebounty.com/416-goldman-sachs-vdp/)

**HSBC**
- HSBC runs a VDP on **Bugcrowd** at `bugcrowd.com/engagements/hsbc-vdp-pro`. Testing started September 27, 2024. — [HSBC VDP on Bugcrowd](https://bugcrowd.com/engagements/hsbc-vdp-pro)
- Also listed directly on HackerOne: `hackerone.com/hsbc`. — [HSBC on HackerOne](https://hackerone.com/hsbc)
- Rules prohibit automated scanners, port scanning, and scripted use of customer-facing forms. Researchers must limit access to customer data. Program page was last updated October 2025.

**Barclays**
- FireBounty lists a responsible disclosure contact at `barclays.responsibledisclosure.com`, with a security.txt snapshot dated 2024-03-01. — [FireBounty Barclays VDP](https://firebounty.com/59043-barclayscom/)
- HackerOne also has a community-curated stub page for Barclays. No public payout or scope details found via public search.
- Open Bug Bounty reports XSS patches to `jobs.barclays.co.uk` in January 2024. — [Open Bug Bounty – Barclays](https://www.openbugbounty.org/reports/53107/)

**Citibank**
- Citi's program runs on both **Bugcrowd** (`bugcrowd.com/citi`) and **HackerOne** (`hackerone.com/citi`). Follows Bugcrowd Vulnerability Rating Taxonomy. — [Citi on Bugcrowd](https://bugcrowd.com/citi); [Citi on HackerOne](https://hackerone.com/citi)
- Citi explicitly states it "will not correspond with you directly, disclose remediation steps, or timeframes" and does not allow public disclosure.

**Wells Fargo**
- Self-hosted policy page at `wellsfargo.com/privacy-security/fraud/responsible-disclosure-program/` with actual submission handled through **HackerOne**. — [Wells Fargo Responsible Disclosure](https://www.wellsfargo.com/privacy-security/fraud/responsible-disclosure-program/)
- Safe harbor: "conduct will be considered authorized conduct and we will not initiate legal action against you" if guidelines are followed. No payout mentioned on the consumer page; appears to be a VDP.

**DBS Bank (Singapore)**
- Runs a Vulnerability Disclosure Programme at `dbs.com/vdp`. Appears to be self-hosted based on the domain. — [DBS VDP](https://www.dbs.com/vdp/default.page)
- No payout details found; likely a VDP (no pay).

**Bank of America**
- No public disclosure program page or bug bounty program found through this research.

### Inferences
- Most major US banks operate VDPs without cash rewards and funnel submissions through managed platforms (HackerOne, Bugcrowd, Synack), not fully self-hosted infrastructure.
- Barclays may use a semi-self-hosted model (barclays.responsibledisclosure.com), but the backend operator is unknown.
- Given HackerOne and Bugcrowd's market dominance, "self-hosted" typically means only the landing page is on the bank's domain while triage/intake is outsourced.

### Gaps
- **Bank of America:** No confirmed VDP or bug bounty program found; their security page was not returned in search results.
- **Specific payout ranges:** No bank publicly lists bounty reward tiers (for the ones with paid programs, amounts are disclosed only on platform pages requiring accounts).
- **Barclays backend platform:** Whether the portal at `barclays.responsibledisclosure.com` is internally managed or outsourced is not confirmed.
- **Paid vs. VDP distinction for JPMorgan:** The public-facing page does not state whether rewards are offered; program terms are behind the Synack portal.

---

## Fintech Companies — Programs Outside HackerOne/Bugcrowd

### Takeaway
Most major fintech companies (PayPal, Stripe, Wise, Coinbase) use managed platforms (HackerOne, Bugcrowd, Intigriti) rather than self-hosting. Robinhood notably moved to Intigriti. Coinbase extended its HackerOne program to cover onchain/smart contract work and uses Cantina for specific on-chain programs.

### Cited Findings

**PayPal**
- PayPal runs its bug bounty through **HackerOne**. The program has awarded more than $6 million to roughly 3,000 ethical hackers. — [HackerOne: PayPal Program Insights](https://www.hackerone.com/blog/program-insights-paypal-security-team)
- Maximum reward raised to $30,000 (up from $10,000); Venmo is also covered. Researchers must hold a verified PayPal account in good standing. — [PortSwigger Daily Swig on PayPal bounty increase](https://portswigger.net/daily-swig/paypal-bug-bounty-increases-to-30k)
- PayPal is considered one of the first financial services companies to run a public bug bounty. — [NBC News: PayPal Institutes Bug Bounty Program](https://www.nbcnews.com/news/amp/wbna47954232)

**Stripe**
- Bug bounty program hosted on **HackerOne** at `hackerone.com/stripe`. Rewards and eligibility are at Stripe's discretion; only the first valid report of a vulnerability is generally rewarded; Stripe employees and contractors are barred. — [Stripe on HackerOne (policy versions)](https://hackerone.com/stripe/policy_versions)

**Wise (formerly TransferWise)**
- Primary program on **Bugcrowd** at `bugcrowd.com/wise`. Reports outside Bugcrowd do not qualify for rewards. Won't take legal action against researchers following guidelines. Wise also maintains a consumer-facing policy at `wise.com/responsible-disclosure`. — [Wise Responsible Disclosure](https://wise.com/responsible-disclosure); [Wise on Bugcrowd](https://bugcrowd.com/wise)
- Bugcrowd case study notes Wise launched as a private program then expanded to public. — [Bugcrowd Case Study: Wise](https://www.bugcrowd.com/customers/wise/)

**Coinbase**
- Main bug bounty runs on **HackerOne**; described as a "best-in-industry million-dollar HackerOne bug bounty program." Extended to cover the Base network, bridge contracts, and Base infrastructure. — [Base documentation on bounty](https://docs.base.org/docs/security)
- Smart contract/onchain work also handled via **Cantina** (separate from HackerOne): program covers onchain products with start date July 8, 2025. — [Cantina: Coinbase onchain bounty](https://cantina.xyz/bounties/2acbecd1-3a5e-44fb-a324-a524c156d690)
- A payout of $30,000 was reported for a major vulnerability via the HackerOne program. — [The Block](https://www.theblock.co/amp/linked/11977/bug-finder-cashes-in-30000-for-discovering-a-major-vulnerability-in-coinbases-systems)

**Robinhood**
- Bug bounty on **Intigriti** at `app.intigriti.com/programs/robinhood/robinhoodbbp`. Rewards based on CVSSv3 scale. — [Robinhood on Intigriti](https://app.intigriti.com/programs/robinhood/robinhoodbbp)
- A separate Robinhood Chain bug bounty runs on **Cantina** with a maximum reward of $1,000,000, starting September 8, 2026. — [Cantina: Robinhood Chain](https://cantina.xyz/bounties/55316f42-3c5e-4746-9bd0-0f18dcbc344b)
- HackerOne also has a Robinhood customer story page. — [HackerOne: Robinhood](https://www.hackerone.com/robinhood)

**Revolut**
- No confirmed bug bounty or VDP details found through this research.

### Inferences
- No major fintech reviewed here self-hosts its primary bug bounty or VDP; all use managed platforms as the intake and triage layer.
- The shift toward Intigriti (for Robinhood) and Cantina (for blockchain/smart contract work) indicates market fragmentation beyond just HackerOne/Bugcrowd.

### Gaps
- **Revolut:** No confirmed VDP or bug bounty details found.
- **Payout ranges for Stripe:** Stripe's HackerOne page doesn't publish a reward table; amounts are at discretion.
- **Revolut, Wise:** Exact current bounty tiers not confirmed; Wise's Bugcrowd page would be authoritative.

---

## US Government VDP Programs

### Takeaway
The US DoD's Vulnerability Disclosure Program (VDP) is the largest US government VDP, managed by DC3 and Bugcrowd, and is unpaid (no bounty for routine reports); the paid "Hack the Pentagon" challenges are separate bounty events on HackerOne. CISA's federal VDP Platform, operated with Bugcrowd, covers 50+ FCEB agencies and is also primarily unpaid, though two agencies launched paid bug bounty pilots in 2023.

### Cited Findings

**CISA VDP Platform**
- Operated by CISA with **Bugcrowd** and EnDyna since 2021. Covers over 50 Federal Civilian Executive Branch (FCEB) agencies, including DHS, EPA, FTC, NASA, and the Department of Treasury. — [Bugcrowd: CISA VDP Annual Report Explained](https://www.bugcrowd.com/blog/cisas-vdp-platform-annual-report-explained/)
- VDP itself is unpaid: researchers submit reports "without receiving compensation in return." — [Bugcrowd: CISA VDP Annual Report Explained](https://www.bugcrowd.com/blog/cisas-vdp-platform-annual-report-explained/)
- In 2023: more than 7,000 vulnerabilities reported (132% increase from 2022), 1,094 validated (82% increase), 307 critical/severe, 872 fixed. — [Bugcrowd: CISA VDP Annual Report Explained](https://www.bugcrowd.com/blog/cisas-vdp-platform-annual-report-explained/)
- Two agencies launched paid bug bounty pilots in 2023: 815 researchers invited, 229 vulnerabilities found, $335,000 in bounty payouts (average ~$1,500 per accepted submission). — [Bugcrowd: CISA VDP Annual Report Explained](https://www.bugcrowd.com/blog/cisas-vdp-platform-annual-report-explained/)
- Funding was confirmed through February 2025; no source confirmed funding extension after that date. — [CISA VDP Platform Fact Sheet 2024 PDF](https://www.cisa.gov/sites/default/files/2025-05/CSSO-VDP%20Platform%20Fact%20Sheet%202024.pdf) (PDF, not parsed)
- The platform exists to help agencies meet Binding Operational Directive (BOD) 20-01, which requires FCEB agencies to publish a VDP. — [Bugcrowd: CISA VDP Annual Report Explained](https://www.bugcrowd.com/blog/cisas-vdp-platform-annual-report-explained/)
- Estimated average savings of $4.5 million in potential breach-related costs. — [Bugcrowd: CISA VDP Annual Report Explained](https://www.bugcrowd.com/blog/cisas-vdp-platform-annual-report-explained/)

**US Department of Defense (DoD)**
- The DoD Vulnerability Disclosure Program (VDP) launched in November 2016. As of March 2024, DC3 processed its 50,000th vulnerability report. — [TechRadar](https://www.techradar.com/pro/us-department-of-defense-claims-to-have-flushed-out-50000-vulnerabilities-with-bug-bounty-program)
- The VDP itself does NOT pay bounties: "a bounty or cash incentives are not awarded for vulnerabilities reported through the VDP." — [HackerOne: Hack the Pentagon blog](https://www.hackerone.com/blog/hack-pentagon-turns-one-hackerone)
- In 2021 the VDP scope was widened to all publicly accessible DoD information systems. — [PortSwigger Daily Swig](https://portswigger.net/daily-swig/us-government-announces-third-hack-the-pentagon-challenge)
- The separate "Hack the Pentagon" bug bounty challenges (run via HackerOne/DoD Digital Services) are paid events. A DIB (Defense Industrial Base) pilot led to remediation of 400+ vulnerabilities saving an estimated $61 million. — [TechRadar](https://www.techradar.com/pro/us-department-of-defense-claims-to-have-flushed-out-50000-vulnerabilities-with-bug-bounty-program)
- DoD has also announced a website for continuous bug bounties (CDAO). — [ExecutiveGov](https://www.executivegov.com/articles/dod-launches-website-for-hack-the-pentagon-initiative)

### Inferences
- CISA's VDP Platform is the US government's primary shared intake mechanism for unpaid vulnerability disclosure; it is a platform service, not a self-hosted deployment.
- DoD's continuous VDP and the Hack the Pentagon challenges are distinct programs operating in parallel.

### Gaps
- **CISA platform status post-February 2025:** No source confirms the platform's funding or continuation after February 2025.
- **Individual agency VDP pages:** Specific scope and submission URLs for each of the 50+ FCEB agencies are not listed in any single public source found.
- **DoD direct VDP portal URL:** The DC3-managed VDP portal URL was not captured from search results; the most accessible path is through Hack the Pentagon's HackerOne page.

---

## UK and EU Government VDP Programs

### Takeaway
The UK NCSC operates a Vulnerability Reporting Service (VRS) through HackerOne since 2018 (unpaid); individual UK government bodies like NHS England and the Welsh Government also have VDPs on HackerOne. The European Commission awarded a major four-year bug bounty contract to YesWeHack in October 2025.

### Cited Findings

**UK NCSC / Government**
- The NCSC launched its Vulnerability Reporting Service (VRS) in 2018 via **HackerOne**, without financial rewards. NCC Group has triaged and managed the program since then. — [BankInfoSecurity: UK NCSC Software Vulnerability Initiative](https://www.bankinfosecurity.com/uk-ncsc-announces-software-vulnerability-initiative-a-28991); [NCC Group: 5 years with NCSC](https://nccgroup.com/us/newsroom/celebrating-five-years-of-collaboration-between-ncc-group-ncsc-on-the-responsible-disclosure-of-vulnerabilities/)
- **NHS England** runs a VDP in collaboration with the NCSC, hosted on **HackerOne**. — [NHS England Security Vulnerability Disclosure](https://www.england.nhs.uk/security-vulnerability-disclosure/)
- **Welsh Government** published its VDP on December 12, 2025, managed by its Cyber Security Operations Centre (CSOC), also on **HackerOne**. Excludes non-exploitable vulnerabilities. — [Welsh Government VDP](https://www.gov.wales/node/73153)
- Joint CVD guidance was published July 15, 2026, by CISA, NSA, Japan's JPCERT/CC, Netherlands' NCSC-NL, and the UK's NCSC-UK — covers how to establish a CVD program including safe harbor language. — [NSA Press Release](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4546549/)

**European Commission / EU**
- The European Commission has run bug bounty programs on open-source assets used by EU institutions since 2019. — [YesWeHack press release](https://www.yeswehack.com/news/european-commission-tender-won-yeswehack)
- In October 2025, the Commission's DIGIT directorate awarded **YesWeHack** a four-year framework contract (cascade model), potentially worth up to €7,679,875, to run bug bounty programs and VDPs. — [BusinessWire: YesWeHack wins EU Commission tender](https://www.businesswire.com/news/home/20251001342504/en/YesWeHack-Won-the-European-Commissions-Latest-Bug-Bounty-Tender)
- The new contract widens scope to more open-source projects and allows other EU institutions to use the framework. — [YesWeHack press release](https://www.yeswehack.com/news/european-commission-tender-won-yeswehack)

**ENISA**
- ENISA published a report in February 2023 on "Developing National Vulnerability Programmes" covering bug bounties in public administrations. No ENISA-run bug bounty or VDP found. — [ENISA: Developing National Vulnerabilities Programmes PDF](https://enisa.europa.eu/publications/developing-national-vulnerabilities-programmes/@@download/fullReport)

### Inferences
- The UK's VRS is unpaid; government VDPs in Europe typically do not offer cash rewards unless a specific paid challenge is run (as the EU Commission has done).
- YesWeHack has become the dominant platform for EU government programs after winning the Commission's framework contract.

### Gaps
- **Specific EU member-state government VDPs:** No comprehensive list of individual EU member-state government VDPs (France, Germany, etc.) was found.
- **NCSC VRS scope details:** The full scope of what systems are covered by the UK VRS was not returned.
- **ENISA VDP:** No evidence found of ENISA operating its own VDP.

---

## Asian Financial and Government VDP Programs

### Takeaway
Adoption is low in Asia: only one bank among 43 tracked in Asia/South America had a VDP as of Q3 2023. Singapore's GovTech is the most mature Asian government entity with multiple programs; South Korea's Financial Security Institute runs a financial-sector bounty. DBS Bank (Singapore) has a self-hosted VDP page.

### Cited Findings

- **Asian bank adoption:** Per the 2024 Wavestone benchmark, across Asia/South America (43 banks, ~46% of global bank assets), only one bank had a VDP as of Q3 2023. — [Wavestone RiskInsight 2024](https://www.riskinsight-wavestone.com/en/2024/02/bug-bounty-insight-and-benchmark-on-the-banking-and-public-sectors-2024/)
- **Cultural friction:** A Brink News piece notes many Asian companies hesitate to run bug bounties, citing cultural reasons and complexity. — [Brink News](https://www.brinknews.com/bug-bounty-programs-will-asian-companies-take-the-leap/)
- **DBS Bank (Singapore):** Maintains a VDP at `dbs.com/vdp`. Appears self-hosted. No confirmed payout. — [DBS VDP page](https://www.dbs.com/vdp/default.page)
- **South Korea Financial Security Institute:** Has run a financial-sector bug bounty since 2019. Expanded in 2022 from internet banking to include mobile apps. Offers rewards; the 2022 expansion was announced with a prize of up to 10 million KRW (~$7,500 USD) for high-severity findings. — [Asiae English: 10M KRW reward for financial vulnerabilities](https://view.asiae.co.kr/en/article/2022080310050053798)
- **Singapore GovTech:** Runs three programs:
  - **VDP** (launched 2019): open to all, no bounty, internet-facing government systems. YesWeHack listing shows 677 reports, last updated September 2025. — [YesWeHack GovTech VDP](https://yeswehack.com/programs/vdp); [GovTech factsheet (Feb 2023)](https://www.tech.gov.sg/files/media/media-releases/Factsheet%20on%20Government%20Crowdsourced%20Vulnerability%20Discovery%20Programmes%20(Updated%20Feb%202023).pdf)
  - **Government Bug Bounty Programme (GBBP)** (launched 2018): seasonal/time-limited paid program. — [GovTech factsheet (Feb 2023)](https://www.tech.gov.sg/files/media/media-releases/Factsheet%20on%20Government%20Crowdsourced%20Vulnerability%20Discovery%20Programmes%20(Updated%20Feb%202023).pdf)
  - **Vulnerability Rewards Programme (VRP)** (launched 2021): year-round, rewards US$250–$5,000 by severity, plus up to US$150,000 for exceptional-impact findings on selected systems. — [SecurityWeek: GovTech VRP](https://www.securityweek.com/singapores-govtech-announces-new-vulnerability-rewards-programme/)
  - Since 2018, GovTech has partnered with 1,000+ researchers to find ~500 valid vulnerabilities. — [SecurityWeek: GovTech VRP](https://www.securityweek.com/singapores-govtech-announces-new-vulnerability-rewards-programme/)
- **National Australia Bank:** Bugcrowd case study confirms NAB ran a bug bounty through Bugcrowd. — [Bugcrowd NAB Case Study PDF](https://www.bugcrowd.com/wp-content/uploads/2023/11/National-Australia-Bank-Case-Study.pdf)

### Inferences
- DBS is likely the only major Asian bank confirmed to operate even a basic VDP (self-hosted). Most Asian banks have neither a VDP nor a bounty.
- Singapore's GovTech stands out as the most sophisticated government bug bounty operator in Asia Pacific, with both unpaid (VDP) and paid (VRP, GBBP) tiers in operation since 2018–2021.

### Gaps
- **ICBC, Ant Financial, Alipay:** No confirmed VDP or bug bounty program found for major Chinese financial institutions.
- **Japanese and Indian banks:** No VDP/bounty programs found for Japanese megabanks (MUFG, Mizuho) or Indian banks (SBI, HDFC).
- **South Korea FSI program details:** No English-language program page URL found; the cited article is the primary source for existence.

---

## Payout Ranges and VDP vs. Paid Bounty Summary

### Takeaway
Paid bug bounties in the financial sector typically range from a few hundred to $30,000 (mainstream financial apps), with crypto/blockchain programs reaching $1M+. The majority of bank programs are VDPs (no pay).

### Cited Findings

- **PayPal:** Max $30,000 via HackerOne. — [PortSwigger](https://portswigger.net/daily-swig/paypal-bug-bounty-increases-to-30k)
- **Coinbase:** Max reward reported at $30,000 for a single vulnerability; blockchain programs via Cantina may be higher. "Best-in-industry million-dollar" language used for HackerOne coverage. — [The Block](https://www.theblock.co/amp/linked/11977/bug-finder-cashes-in-30000-for-discovering-a-major-vulnerability-in-coinbases-systems); [Base documentation](https://docs.base.org/docs/security)
- **Robinhood Chain (Cantina):** Max $1,000,000 (blockchain-specific program, starting Sept 2026). — [Cantina: Robinhood Chain](https://cantina.xyz/bounties/55316f42-3c5e-4746-9bd0-0f18dcbc344b)
- **Singapore GovTech VRP:** US$250–$5,000 standard; up to US$150,000 for exceptional-impact findings on selected systems. — [SecurityWeek: GovTech VRP](https://www.securityweek.com/singapores-govtech-announces-new-vulnerability-rewards-programme/)
- **CISA/DoD paid pilots (2023):** $335,000 total across two agencies; average ~$1,500 per accepted submission. — [Bugcrowd: CISA VDP report](https://www.bugcrowd.com/blog/cisas-vdp-platform-annual-report-explained/)
- **South Korea FSI:** Up to ~10 million KRW (~$7,500 USD). — [Asiae English](https://view.asiae.co.kr/en/article/2022080310050053798)

**VDP-only (no pay) programs confirmed:**
- DoD VDP (DC3)
- CISA VDP Platform (core program; paid bounty is separate opt-in)
- JPMorgan Chase Responsible Disclosure (likely VDP only — no payout stated)
- Wells Fargo Responsible Disclosure (no payout stated)
- DBS Bank VDP
- UK NCSC VRS
- NHS England VDP
- Welsh Government VDP
- Singapore GovTech VDP

**Paid bounty programs confirmed:**
- PayPal (HackerOne) — up to $30,000
- Stripe (HackerOne) — undisclosed tiers
- Wise (Bugcrowd) — tiers not confirmed
- Coinbase (HackerOne) — up to $1M claimed
- Robinhood (Intigriti) — CVSSv3-based tiers
- Goldman Sachs (HackerOne) — tiers not confirmed
- CISA two-agency pilots (Bugcrowd) — ~$1,500 avg
- Singapore GovTech VRP — up to $150,000
- South Korea FSI — up to ~$7,500

### Inferences
- No major traditional bank publicly advertises a paid bug bounty with specific reward tiers; the sector's programs are overwhelmingly VDPs.
- Crypto/blockchain companies and government programs with targeted scope (like Singapore's high-severity tier) represent the highest public payouts.

### Gaps
- **Goldman Sachs, Barclays, HSBC payout tiers:** Not publicly confirmed; platform pages require researcher accounts for full details.
- **Bank of America VDP existence:** Not confirmed.
- **Revolut program details:** Not confirmed.
