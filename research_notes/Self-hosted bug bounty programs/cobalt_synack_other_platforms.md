# Bug Bounty and VDP Programs on Cobalt, Synack, Immunefi, Federacy, and Other Managed Platforms

## What notable companies use Cobalt.io for their bug bounty programs?

### Takeaway
Cobalt.io is NOT a traditional bug bounty platform — it is a Pentest as a Service (PTaaS) company that explicitly markets itself as "The modern alternative to bug bounty programs." Companies use it for managed, vetted pentesting engagements rather than open crowdsourced vulnerability discovery.

### Cited Findings
- Cobalt.io's solutions page markets the product as "The modern alternative to bug bounty programs," criticizing crowdsourced bug bounty programs for producing mostly non-vulnerabilities, submissions with too little detail, and unpredictable budgeting — [Cobalt.io vs Bug Bounty Providers](https://www.cobalt.io/solutions/cobalt-vs-bug-bounty-providers)
- Cobalt's customer page lists over 1,500 companies as customers for PTaaS services — [Cobalt Customers](https://www.cobalt.io/customers)
- Named Cobalt customers from case studies include: **Aircall** (cloud phone system), **Algolia** (search API), **Zest AI** (credit risk / AI lending), **Insurity**, **PowerSchool**, **DigitalRoute**, **Syndio**, **Quinyx**, **Credit Karma**, **Axel Springer**, **Pendo**, **Santa Cruz County Bank** — [Cobalt Case Studies](https://www.casestudies.com/company/cobalt); [Cobalt Customers Page](https://www.cobalt.io/customers)
- Cobalt also has pages for **BitGo** and **Coins.ph** as customers — [cobalt.io/bitgo](https://cobalt.io/bitgo); [cobalt.io/coins-ph](https://cobalt.io/coins-ph)
- In 2025, Cobalt delivered over 31,000 testing days and grew its customer base by over 7% — [BusinessWire 2025](https://www.businesswire.com/news/home/20251218649449/en/Cobalt-Closes-2025-With-Unprecedented-Scale-Breakthrough-AI-Innovation-and-88-G2-Badges)
- In August 2025, Cobalt launched a hybrid AI and human-led pentesting approach — [Cobalt Press Page](https://www.cobalt.io/press/tag/news/page/6)
- A third-party aggregator (TheirStack) claims Airbnb, Shopify, and Twitter use Cobalt, but this could not be independently verified — [TheirStack](https://theirstack.com/de/technology/cobalt) (unverified — treat as low confidence)

### Inferences
- Cobalt.io should not be listed alongside traditional bug bounty platforms; its model is fundamentally different (scoped, time-boxed pentesting with vetted testers vs. open crowdsourced bounty hunting).
- Companies choosing Cobalt likely want compliance-oriented, structured testing rather than an ongoing public-facing bug bounty.

### Gaps
- Cobalt's customer page does not publicly list all 1,500+ clients by name; only those featured in case studies are publicly identified.
- The distinction between Cobalt "bug bounty" customers (rare) vs. PTaaS customers (the norm) is unclear without direct program pages.

---

## What companies are on Synack's Red Team platform? Are any programs public?

### Takeaway
Synack is an invite-only, highly vetted security testing platform (not a traditional bug bounty) that serves primarily government and enterprise clients. No paying, public-facing bug bounty programs exist; Synack runs a separate unpaid responsible disclosure portal for public submissions.

### Cited Findings
- Synack's Red Team is explicitly described as "not a bug bounty program" — it is a tight-knit community of skilled ethical hackers selected through rigorous vetting including resume review, technical assessment, background/ID verification, and behavioral interviews — [Synack Red Team page](https://www.synack.com/synack-red-team/)
- Fewer than 10% of SRT applicants are accepted according to third-party sources — [Hands-On Bug Hunting for Penetration Testers](https://m.aikan.qq.com/read/1036699440/39)
- Synack operates **responsibledisclosure.com**, which hosts public, unpaid VDP programs on behalf of customers — programs are open to the public including SRT members, but no bounties are paid — [Synack Red Team](https://www.synack.com/?p=20934)
- Synack does not operate public, bounty-paying programs to avoid incentivizing less-than-ethical hacking — [Synack Red Team](https://www.synack.com/?p=1460)
- Customers include: **U.S. Department of Defense**, **U.S. Department of Health and Human Services**, other U.S. government agencies, and private enterprises — [Synack profile](https://episteme.tllm.fr/wiki/Synack)
- In September 2016, the DoD awarded a joint $7 million crowdsourced security contract to HackerOne and Synack. Synack's contract used highly vetted researchers to test sensitive DoD IT assets — [Intelligence Community News](https://intelligencecommunitynews.com/department-of-defense-awards-7-million-crowdsourced-security-contracts-to-hackerone-and-synack/)
- In August 2025, Synack launched **Sara (Synack Autonomous Red Agent)**, an AI-based pentesting agent working alongside human SRT members — [Synack profile](https://episteme.tllm.fr/wiki/Synack)
- Individual campaigns are assigned based on internal researcher rankings; some campaigns are invite-only even within the SRT — [ResumeGeni](https://resumegeni.com/jobs/synack-red-team-pentester-synacksrt-ca3bfd99fb)

### Inferences
- Synack effectively operates as a managed security testing firm with a curated researcher pool, closer to a managed MSSP than an open bug bounty platform.
- Government use is a core differentiator for Synack compared to other platforms.

### Gaps
- The specific list of private enterprise Synack customers is not publicly disclosed.
- Whether any civilian/enterprise Synack programs have public-facing VDP pages on responsibledisclosure.com could not be confirmed.
- No 2025-specific updates to DoD or government contracts were found.

---

## What Web3/crypto projects run bounty programs on Immunefi? What are top payouts?

### Takeaway
Immunefi is the dominant Web3 bug bounty platform, hosting 287+ active programs as of late 2025 with over $162 million in total available bounties and $110 million+ paid out since founding. MakerDAO's $10 million max is the largest program; several DeFi protocols offer $1M–$3M max bounties.

### Cited Findings

**Platform Stats:**
- Immunefi has paid out over $110 million in bug bounties since inception — [Immunefi Hackers Page](https://immunefi.com/hackers/)
- As of 2025, over $162 million in bug bounties is available across participating projects — [Immunefi Hackers Page](https://immunefi.com/hackers/)
- Immunefi paid out close to $11 million in 2025 alone for critical crypto vulnerabilities — [Security Alliance DarkMode 2026](https://darkmode.securityalliance.org/darkmode-2026/talk/P8GGKC/)
- One source reports 287 active bug bounty programs as of November 2025 — [MEXC guide on Immunefi](https://www.mexc.com/tr-CT/learn/article/what-is-immunefiimu-a-complete-guide-to-web3s-leading-security-platform/1) (secondary source; verify against immunefi.com)
- Immunefi earns a 10% commission on bounty payouts — [The Block](https://www.theblock.co/post/301025/web3-immunefi-ethical-hacker-payouts)
- Immunefi claims the fastest response time in the industry (self-reported) — [Immunefi Hackers Page](https://immunefi.com/hackers/)

**Record Payouts (Largest All-Time):**
- **Wormhole**: $10 million paid to whitehat satya0x — the largest bug bounty in software history at time of payment (2022) — [Immunefi Hackers Page](https://immunefi.com/hackers/)
- **Aurora**: $6 million paid to whitehat pwning.eth — [Immunefi Hackers Page](https://immunefi.com/hackers/)
- **Polygon**: $2.2 million paid to whitehat Leon Spacewalker — [Immunefi Hackers Page](https://immunefi.com/hackers/)
- **Optimism**: $2 million paid to whitehat Saurik — [Immunefi Hackers Page](https://immunefi.com/hackers/)

**Notable High-Paying Active Programs (Max Bounties):**
- **MakerDAO (Sky/Maker)**: $10 million max bounty — the platform's largest program, covering smart contracts and web/apps — [Decrypt](https://decrypt.co/92653/makerdao-launches-record-10m-bug-bounty-program-on-immunefi); [CoinTelegraph](https://cointelegraph.com/news/makerdao-launches-biggest-ever-bug-bounty-with-10m-reward)
- **Ethena**: $3 million max — [Immunefi bug bounty listing (scraped Oct 2026)](https://immunefi.com/bug-bounty/)
- **Arbitrum**: $2 million max program in operation since August 2021 — [Arbitrum Foundation Forum](https://forum.arbitrum.foundation/t/immunefi-september-2025-security-council/29972)
- **Kamino (Solana)**: Up to $1.5 million, launched October 2025 — described as Solana's largest bug bounty program at launch — [MEXC guide](https://www.mexc.com/tr-CT/learn/article/what-is-immunefiimu-a-complete-guide-to-web3s-leading-security-platform/1)
- **DeXe Protocol**: $500K max — [Immunefi listing](https://immunefi.com/bug-bounty/)
- **SSV Network**: $250K max vault ($428.7K TVL) — [Immunefi listing](https://immunefi.com/bug-bounty/)
- **Starknet**: Multiple programs (Web & SC, Blockchain/DLT) each up to $250K — [HackenProof listing](https://hackenproof.com/programs) (note: Starknet may list on multiple platforms)
- **ENS (Ethereum Name Service)**: $250K max — [Immunefi listing](https://immunefi.com/bug-bounty/)
- **Lombard Finance**: $250K max — [Immunefi listing](https://immunefi.com/bug-bounty/)
- **Scroll**: Up to $1 million (per November 2025 article) — [MEXC guide](https://www.mexc.com/tr-CT/learn/article/what-is-immunefiimu-a-complete-guide-to-web3s-leading-security-platform/1)
- **Ethereum Foundation**: $50K max for Infrastructure category; critical smart contract bugs minimum $10K — listed on Immunefi, updated November 17, 2025 — [immunefi.com](https://immunefi.com/bug-bounty/immunefi/information/)
- **The Graph**: $50K max, total paid $1.6M — [Immunefi listing](https://immunefi.com/bug-bounty/)
- **Compound**: Renewed Immunefi partnership January 2026; Year-one results: $6,000 distributed across 69 reports — [Tally/Compound Governance](https://tally.xyz/gov/compound/proposal/522)

**Platform Access:**
- Immunefi is open to all security researchers with no invitation required — [Immunefi Hackers Page](https://immunefi.com/hackers/)
- Immunefi is trusted by over 330 projects including ChainLink, SushiSwap, MakerDAO, Wormhole — [The Block](https://www.theblock.co/post/172008/web3-bug-bounty-platform-immunefi-raises-24-million-in-series-a-funding)

### Inferences
- Immunefi has become the de facto standard for Web3/DeFi bug bounties, with maximum bounties often 10-100x higher than traditional software bug bounty programs.
- The $10M MakerDAO program and large DeFi payouts reflect the extreme value at risk in on-chain smart contracts (protocol TVL in the billions).

### Gaps
- A full ranked list of all 287 Immunefi programs by max payout is not publicly available in scraped/search form without iterating through all pages.
- Uniswap's bounty program details on Immunefi were not confirmed in search results.
- Aave's specific bounty ceiling on Immunefi was not confirmed.
- The exact current status of the MakerDAO program post-rebrand (MakerDAO became Sky) was not confirmed.

---

## What programs exist on Federacy?

### Takeaway
Federacy is a Y Combinator-backed startup-focused bug bounty platform offering low-cost managed programs, but it does not publicly list its client companies. Information is sparse and primarily dates from its 2018 launch; no comprehensive 2025 program listing was found.

### Cited Findings
- Federacy is a Y Combinator Summer 2018 company founded to make bug bounty programs accessible to startups — [TechCrunch](https://techcrunch.com/2018/08/10/federacy-wants-to-put-bug-bounty-programs-in-reach-of-every-startup/)
- Federacy offers two tiers: a free **Disclosure** tier (vulnerability inbox + disclosure policy) and a **Bug Bounty** tier at $599/month — [federacy.com/bugbounties](https://www.federacy.com/bugbounties)
- Also offers managed programs with shared Slack channel and triage help — [federacy.com/bugbounties](https://www.federacy.com/bugbounties)
- Both public (open to all researchers) and private (selected researchers) programs are available — [Startup Bahrain](https://startupbahrain.com/news/federacy-aims-to-bring-bug-bounty-programs-accessible-to-everyone/)
- One named client: **Paladin Data Insurance** partnered with Federacy for a bug bounty program — [Startup Bahrain](https://startupbahrain.com/news/federacy-aims-to-bring-bug-bounty-programs-accessible-to-everyone/)
- Competitors include Bugcrowd, Detectify, and PortSwigger per CB Insights — [CB Insights](https://www.cbinsights.com/company/federacy/alternatives-competitors)

### Inferences
- Federacy likely has a small number of programs given its startup-oriented, low-cost model; its primary differentiator is price accessibility rather than enterprise scale.
- The lack of any 2025 news coverage or press releases raises questions about whether the platform remains actively maintained.

### Gaps
- No public listing of Federacy's current client companies or active programs was found.
- No 2025 activity (new features, new clients, press releases) was identified — platform status is uncertain.
- Payout ranges for individual programs are not disclosed on the platform's public pages.

---

## Are there any other notable managed platforms (SafeHats, HackenProof, Vulnerability Lab, etc.)?

### Takeaway
HackenProof is the most notable alternative platform for Web3 programs with 400+ active programs; SafeHats serves the Indian/enterprise market; Standoff Bug Bounty (Positive Technologies) is growing rapidly in the Russian/CIS market. Vulnerability Lab's current status as a managed platform could not be confirmed.

### Cited Findings

**HackenProof:**
- HackenProof reports 400+ active bug bounty programs as of 2025 — [HackenProof](https://hackenproof.com/what-is-hackenproof)
- Notable clients include: **Ethereum Foundation**, **OKX**, **CoinGecko**, **Sui Foundation**, **NEAR Protocol**, **Gate.io**, **VeChain**, **Aurora Labs**, **Avalanche**, **Zoomex** (joined June 2025), **1inch** (expanded program) — [HackenProof Blog](https://blog.hackenproof.com/product-news/what-is-hackenproof/); [HackenProof Programs Page](https://hackenproof.com/programs)
- Top programs from current listing (Page 1): NAVI Protocol $300K, Starknet Web & SC $250K, Starknet Blockchain/DLT $250K, Starknet Staking $100K, Zest Protocol Smart Contracts $100K, Hyperbridge Protocol $50K — [HackenProof Programs](https://hackenproof.com/programs)
- Other programs listed: WhiteBIT, Allbridge, Polygon POS, INIT Capital Web, Gear Protocol, Aptos — [HackenProof Programs page](https://hackenproof.com/programs?page=8)
- HackenProof focuses heavily on Web3/blockchain security alongside traditional web/app programs

**SafeHats:**
- SafeHats is operated by **Instasafe Technologies**, headquartered in Bengaluru, India — [Support.instasafe.com](https://support.instasafe.com/portal/en/kb/articles/what-is-safehats)
- Offers both public (open to all researchers) and private (invite-only) programs — [AlternativeTo](https://alternativeto.net/software/safehats-bug-bounty/about/)
- Pricing: ~$500–$1,000/month subscription or pay-per-valid-bug model (unverified third-party figures) — [AlternativeTo](https://alternativeto.net/software/safehats-bug-bounty/about/)
- Enterprise-focused with 24/7 support, scoping assistance, triage, and remediation guidance — [TechJockey](https://techjockey.com/detail/instasafe-safehats)
- No specific client names or programs found in public searches

**Standoff Bug Bounty (Positive Technologies):**
- Platform more than doubled the number of programs in 2025 to 233 programs (a 2.2x increase over 2024) — [Positive Technologies 2025 Report](https://global.ptsecurity.com/en/about/news/standoff-bug-bounty-year-end-results-32-of-finds-are-high-and-critical-level-vulnerabilities/)
- Researcher community grew to 32,000 registered bug hunters in 2025 (up 74%) — [Positive Technologies 2025 Report](https://global.ptsecurity.com/en/about/news/standoff-bug-bounty-year-end-results-32-of-finds-are-high-and-critical-level-vulnerabilities/)
- 32% of finds were high or critical severity — [Positive Technologies 2025 Report](https://global.ptsecurity.com/en/about/news/standoff-bug-bounty-year-end-results-32-of-finds-are-high-and-critical-level-vulnerabilities/)
- Primarily serves Russian/CIS market companies

**Detectify:**
- Detectify Crowdsource is NOT a traditional company-facing bug bounty platform; instead researchers submit findings against common web technologies that protect all companies using that technology — [Detectify Blog](https://blog.detectify.com/news/detectify-launches-a-crowd-based-security-program-to-ensure-an-always-updated-service/)
- Pays researchers based on number of unique hits their submission generates — [Detectify Crowdsource FAQs](https://blog.detectify.com/news/detectify-crowdsource-faqs/)
- The program was originally processed through Bugcrowd; current 2025 status not confirmed

**Vulnerability Lab:**
- No reliable 2025-specific information on Vulnerability Lab as an active managed bug bounty platform was found in search results

### Inferences
- HackenProof is effectively Immunefi's main competitor in the Web3 space with significant overlap in clients.
- Standoff Bug Bounty is emerging as a significant platform in the CIS/Russian market and may be unknown to Western researchers.
- Detectify has pivoted from a traditional bug bounty model to an asset-protection-focused crowdsource model.

### Gaps
- SafeHats' specific client list and active programs are not publicly disclosed.
- Vulnerability Lab's current operational status as a managed bug bounty platform could not be confirmed.
- No information found on other regional platforms (e.g., Yogosha in France, Intigriti/YesWeHack are European but not covered here per scope).

---

## Which of these platforms are invite-only vs open to all researchers?

### Takeaway
Most platforms offer both public and private program options; Synack is the only platform where ALL programs require researcher vetting. Immunefi and HackenProof are fully open to researchers.

### Cited Findings
- **Synack**: Entirely invite-only/curated — fewer than 10% of applicants accepted to the SRT; no open public bounty programs — [Synack Red Team](https://www.synack.com/synack-red-team/)
- **Synack VDP**: Public, unpaid VDP programs exist at responsibledisclosure.com — open to all, but no monetary rewards — [Synack](https://www.synack.com/?p=20934)
- **Immunefi**: Open to all researchers — no invitation required — [Immunefi Hackers Page](https://immunefi.com/hackers/)
- **HackenProof**: Open to all researchers for public programs; private programs exist for select researchers — [HackenProof](https://hackenproof.com/what-is-hackenproof)
- **SafeHats**: Both private (invite-selected researchers) and public (open to full hacker network) options available — [AlternativeTo](https://alternativeto.net/software/safehats-bug-bounty/about/)
- **Federacy**: Both public and private program options — [Startup Bahrain](https://startupbahrain.com/news/federacy-aims-to-bring-bug-bounty-programs-accessible-to-everyone/)
- **Cobalt.io**: Not a public bug bounty platform — testers must apply and be vetted to join the Cobalt Core researcher pool — [Cobalt.io](https://www.cobalt.io/solutions/cobalt-vs-bug-bounty-providers)

### Inferences
- For open/public research access, Immunefi is the most accessible major platform.
- Synack functions more as a staffing/consulting service than a public-facing platform.

### Gaps
- The exact acceptance criteria and vetting process for Cobalt Core researcher applications were not detailed in search results.

---

## What are typical payout ranges on each platform?

### Takeaway
Immunefi has by far the highest ceiling payouts (up to $10M+) driven by Web3 smart contract risk; traditional platforms like Cobalt and Synack use fixed/negotiated pricing rather than per-vulnerability bounties.

### Cited Findings
- **Immunefi**: $1,000 (low) to $10 million+ (critical); median critical payout ~$52,800 (unverified, secondary source); total $110M+ paid out — [Immunefi Hackers Page](https://immunefi.com/hackers/); [MEXC guide](https://www.mexc.com/tr-CT/learn/article/what-is-immunefiimu-a-complete-guide-to-web3s-leading-security-platform/1)
- **HackenProof**: Ranges vary widely by program; examples from listing: $200 (Bitkub) to $300,000 (NAVI Protocol); many programs in $5K–$100K range — [HackenProof Programs](https://hackenproof.com/programs)
- **Cobalt.io**: NOT per-vulnerability bounties — uses subscription/PTaaS pricing; no per-bug payouts to researchers — [Cobalt.io](https://www.cobalt.io/solutions/cobalt-vs-bug-bounty-providers)
- **Synack**: No public per-bug payout data; researchers are compensated based on internal rankings and campaign assignments — [Synack Red Team](https://www.synack.com/synack-red-team/)
- **SafeHats**: ~$500–$1,000/month for companies (platform fee); per-valid-bug model also available for company-side costs — [AlternativeTo](https://alternativeto.net/software/safehats-bug-bounty/about/) (unverified third-party figure)
- **Federacy**: $599/month for company-side Bug Bounty tier; researcher payout ranges not disclosed — [federacy.com](https://www.federacy.com/bugbounties)
- **Standoff Bug Bounty**: Not disclosed in available sources

### Inferences
- The extremely high Immunefi ceilings are structurally justified: a critical bug in a DeFi protocol with $10B TVL could enable theft of the entire protocol, so $10M in bounty is rational.
- Traditional platforms (Cobalt, Synack) avoid published per-bug payout tables because they use time-and-materials or subscription pricing.

### Gaps
- Researcher-side payout ranges for Synack's private campaigns are not public.
- Average or median payout data for HackenProof and Federacy programs was not found.
- Standoff Bug Bounty payout ranges were not found in available sources.
