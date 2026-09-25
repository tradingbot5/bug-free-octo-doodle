SKILL: Comprehensive Manual XSS Discovery, Exploitation & WAF Bypass
A structured, context-first methodology for finding and exploiting XSS in any modern web application, under any WAF, in any condition — using only the browser, a proxy, and your own reasoning.

Core Philosophy
Modern XSS hunting is not a payload problem. It is a parsing discrepancy problem. The WAF and the backend are different parsers. Your job is to find requests that the WAF reads as benign but the browser executes as malicious. Research from WAFFLED (ACSAC 2025) confirmed 1,207 bypasses across five major WAFs by targeting non-malicious request components rather than payloads. WAF Manis (IEEE S&P 2024) discovered 311 protocol-level evasions affecting all tested WAFs and frameworks.

Three rules govern everything:

Context before payload. Never inject without knowing the exact output context (HTML body, attribute, JS string, URL, CSS).

Reflection ≠ execution ≠ impact. A reflected string is not a vulnerability. A blocked payload is not a secure application. Only confirmed JavaScript execution counts.

The WAF is a speed bump, not a wall. Blocklists are finite. The space of equivalent HTML/JS syntax is infinite. That asymmetry is your weapon.

Every step below is performed manually, with your own eyes, hands, and reasoning. No automated scanners. No payload fuzzers. The browser and a proxy are your only interfaces to the target.

Phase 1: Manual Reconnaissance & Input Mapping
Step 1.1: Walk the Application by Hand
Open the target in a browser with Developer Tools open (F12). Navigate every link, form, button, and menu item manually.

For each page, observe:

URL structure — which parameters appear in the query string, in the path, in the fragment?

Forms — every <input>, <textarea>, <select>, <button>, and <form> element. Record the name attribute, the method, and the action.

API calls — open DevTools → Network tab. Reload the page and watch every XHR/fetch request. Note the endpoints, the request bodies, the query strings, and the headers.

Cookies — DevTools → Application → Cookies. Note every cookie name, value, and whether its value looks user-controlled.

Local/Session storage — DevTools → Application → Storage. Note every key.

WebSocket traffic — DevTools → Network → WS filter. Note every message format.

Click everything. Submit every form with garbage input. Watch what appears in the URL, the DOM, and the network tab.

Step 1.2: Inventory Every Input Vector Manually
Create a spreadsheet. One row per input. Columns:

Column	What to Record
Page / URL	Where the input lives
Parameter name	q, id, redirect, name, file, etc.
Location	Query / Path / Header / Cookie / POST body / Fragment
Method	GET / POST / PUT / PATCH / DELETE
Auth required	Yes / No / Role
Visible in response	Does the value appear in the HTML? Where?
Storage behavior	Is it saved? Does it appear on a later page?
Suspected context	HTML / attribute / JS / URL / CSS
Walk each page manually and fill this in. Do not skip pages because they "look boring" — boring pages are often where reflection lives.

Step 1.3: Discover Hidden Inputs Manually
Hidden parameters don't appear in the UI. Find them by:

Reading JavaScript source directly. Open DevTools → Sources. Search every JS file for fetch(, XMLHttpRequest, axios, $.ajax, location.search, URLSearchParams, getParam, and parameter name strings. Every string literal that looks like a parameter name is a candidate.

Inspecting form validation scripts. Client-side validators often reference parameter names that aren't in the visible form.

Checking redirect chains. DevTools → Network → check the Location header on 302 responses. Redirect parameters are often exploitable.

Trying common names manually. Append ?debug=1, ?test=1, ?admin=true, ?callback=test, ?jsonp=test, ?format=json to existing endpoints and observe changes.

Priority targets: Parameters reflected into HTML, inserted into attributes, inserted into JavaScript, or stored and later rendered to privileged users.

Phase 2: Manual Context Identification & Reflection Analysis
Step 2.1: Inject Canary Strings Manually
For each parameter, submit a unique canary like xsscanary123. Submit it through the normal browser UI — type it into the form, put it in the URL, paste it into the API call. Do not use an automated fuzzer.

Then, in the response:

View page source (Ctrl+U). Search for xsscanary123.

Inspect the DOM (DevTools → Elements). Search for xsscanary123.

Check the Network response body in DevTools for XHR endpoints.

If the canary appears in the response, you have a reflection. Record exactly where it lands.

Step 2.2: Determine the Output Context Manually
Use browser DevTools → Elements to inspect the exact DOM node where your canary sits. Context classification is the single most important step in XSS hunting.

Context	How to Recognize It	Escape Strategy
HTML body	Canary sits between tags: <div>CANARY</div>	Inject <script> or event handler
Quoted attribute	Canary sits inside ="..."	Break out with " or inject handler
Unquoted attribute	Canary sits inside =... with no quotes	Inject space + handler
JS string	Canary sits inside var x = "..."	Close string, inject </script> or JS
JS expression	Canary is an argument: fn(CANARY)	Inject JS directly
URL/href	Canary sits inside href="..." or src="..."	Use javascript:
CSS	Canary sits inside <style>...</style>	CSS injection to XSS
Write down the exact context. It determines every payload you will try.

Step 2.3: Analyze Character Transformations Manually
Submit each of these characters one at a time and observe what comes back:

text
< > " ' ` \ & / ; = ( ) { } : $
For each one, record:

Did it appear unchanged?

Was it HTML-encoded (&lt;)?

Was it stripped entirely?

Was it double-encoded (%26lt%3B)?

Was it normalized to something else?

Critical question: Which decoder runs at this reflection point? URL decoder, HTML entity decoder, JS unescaper, or none? Encoding is the most productive bypass class — but only if you encode for the decoder that actually runs.

If < survives but > is stripped, you may be able to use an unclosed tag that the browser auto-closes. If " is escaped but ' isn't, you have a breakout in the single-quote context. If everything is encoded, look for a second context elsewhere on the page (there is almost always one).

Phase 3: Manual WAF Bypass — Parsing Discrepancy Techniques
This is the core of the skill. WAF bypass is not about obfuscating payloads. It is about exploiting differences between how the WAF and the backend parse the same HTTP request.

Step 3.1: Content-Type Confusion (Primary Vector)
WAFFLED confirmed 1,207 bypasses across five major WAFs by targeting non-malicious request components. More than 90% of websites accept both application/x-www-form-urlencoded and multipart/form-data interchangeably.

Manual method:

Identify an endpoint that accepts JSON (visible in the Network tab).

Use the browser DevTools → Network → right-click the request → Edit and Resend.

Change Content-Type: application/json to application/x-www-form-urlencoded and reformat the body accordingly.

Send the request. Observe whether the backend still parses it.

Now try the reverse: send a form-encoded body with a JSON Content-Type header.

Test multipart/form-data by crafting a manual multipart body with a deliberate boundary mismatch.

Content-Type blind spots to fuzz manually:

Content-Type	Risk if Accepted
text/xml	XXE injection
application/x-www-form-urlencoded	Bypasses JSON-specific WAF rules
application/graphql	Hidden GraphQL endpoint
application/x-yaml	YAML deserialization
multipart/form-data	WAF boundary parsing truncation
Multipart boundary manipulation (manual): Craft a body where the first boundary token is deliberately malformed but a later boundary is valid. The WAF's parser may stop at the first boundary and see harmless data, while the backend's parser skips the malformed one and reads the malicious segment.

Step 3.2: HTTP Parameter Pollution (HPP)
HPP bypasses WAFs by splitting a payload across duplicate keys. The WAF inspects the first value, but the application uses the last value.

Manual method:

text
?param=harmless&param=<script>alert(1)</script>
In DevTools, edit the URL directly and add a duplicate parameter. Observe the response. If the WAF only scans the first param value (harmless), the malicious second value passes inspection but the backend uses it.

Try both orders:

text
?param=<script>alert(1)</script>&param=harmless
?param=harmless&param=<script>alert(1)</script>
Different frameworks pick different values (first, last, or concatenation). Test all three.

Step 3.3: Encoding Stacks (Manual)
Which decoder runs where:

Context	Decoder	Payload Technique
HTML body	HTML entity decoder	&#x3c;script&#x3e;
HTML attribute	HTML entity decoder	&#x22; onmouseover=alert(1)
URL parameter	URL decoder	%3Cscript%3E
JS string	JS unescaper	\u003cscript\u003e
Nested encoding	Multiple decoders	Double/triple URL encoding
Double encoding example:

text
WAF sees: %253Cscript%253E
Browser decodes twice: <script>
Stacking three encodings inside a single payload defeats signature-based WAF regex filters. Build these manually in DevTools and observe which layer the browser decodes.

Step 3.4: Event Handler Alternatives
Cloudflare blocks well-known handlers (onclick, onload, onerror, onmouseover). Underexplored alternatives confirmed to bypass as of 2026:

html
<div oncontentvisibilityautostatechange=alert(document.domain) style=content-visibility:auto>
This is the CSS Containment API's event attribute. Cloudflare's WAF did not filter it as of April 2026. The attribute triggers when the element's content-visibility state changes, requiring only that the element be rendered with content-visibility: auto.

Additional handlers to test manually:

onanimationstart — CSS animation events

ontransitionend — CSS transition events

onpointerdown — Pointer API

ondragstart — Drag API

onauxclick — Middle-mouse click (also enables clickjacking)

Submit each one manually and observe whether the WAF blocks it. If blocked, wrap it in HTML entity encoding or split it across attributes.

Step 3.5: SVG Injection
SVG tags are frequently overlooked by tag-based filtering.

html
<svg onload=alert(1)>
<svg/onload=alert(document.cookie)>
<svg onload=alert%26%230000000040"1')>
The <svg> tag bypasses tag filters, and onload executes when the SVG loads. A real-world reflected XSS disclosure in February 2026 confirmed that <svg onload=alert%26%230000000040"1')> bypassed Cloudflare's WAF.

Submit manually and watch the browser console for the alert. If blocked, try alternate SVG event handlers: onbegin, onend, onrepeat.

Step 3.6: Case Variation & Keyword Splitting
HTML is case-insensitive. If the filter does literal case-sensitive matching:

html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>
If the filter strips <script> exactly once non-recursively:

html
<scr<script>ipt>alert(1)</scr</script>ipt>
Whitespace and control characters between tag name and attributes also work:

html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
<img src=x onerror=alert(1)>
Submit each variant manually, one at a time, and observe the WAF response (usually a 403 or 1020 for Cloudflare).

Step 3.7: Polyglot Payloads
Polyglot payloads execute in multiple injection contexts simultaneously — HTML, attribute, JavaScript string, URL — without modification. A well-crafted polyglot can break out of an attribute, close a script tag, and execute JavaScript from a single string.

Example polyglot:

text
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
Submit manually in a context where you don't yet know the exact sink. Watch which fragment of the polyglot fires.

Step 3.8: Protocol-Level Techniques (Manual)
If the target uses HTTP/2 (visible in DevTools → Network → Protocol column), the SPCA research (ACM Web Conference 2026) demonstrated structure-only manipulation of stream priorities and dependencies bypasses modern WAFs with a success rate exceeding 89%. SPCA operates without altering payload content — it relies solely on RFC-compliant manipulation of stream priority weights and dependency trees.

Performing this manually requires a custom HTTP/2 client that allows you to specify stream priorities and dependencies. If you don't have one, note the target uses HTTP/2 and flag it for later structured testing.

If the target uses HTTP/1.1, test request smuggling manually: send a request with both Content-Length and Transfer-Encoding headers and observe how the WAF and backend interpret the body boundary differently.

Phase 4: Manual DOM XSS & Client-Side Analysis
Step 4.1: Read the JavaScript by Hand
Open DevTools → Sources. Read every JS file that runs on the target. Search for these specific strings:

Sources (where attacker-controllable data enters):

javascript
location.href
location.search
location.hash
location.pathname
document.URL
document.referrer
window.name
postMessage
localStorage
sessionStorage
Sinks (where data becomes executable):

javascript
innerHTML
outerHTML
insertAdjacentHTML
document.write
document.writeln
eval
Function
setTimeout
setInterval
src
href
setAttribute
iframe.src
script.src
For every source you find, trace manually where its value flows. Look for =, function arguments, string concatenation, and template literals. Do not flag a sink merely because it exists — establish attacker-controlled reachability by injecting canary values and watching the DOM.

Step 4.2: Framework-Specific Sinks
Read the framework's source or documentation to understand which APIs bypass escaping:

Framework	Dangerous API
React	dangerouslySetInnerHTML
Vue	v-html
Angular	bypassSecurityTrustHtml
jQuery	.html(), .append()
Vanilla JS	innerHTML, document.write
Search the JS bundle for these strings. If any are present and reachable from a source, you likely have a DOM XSS.

Step 4.3: Cookie Injection → DOM XSS
When applications set cookie values based on user input and those cookies are later read into DOM sinks (innerHTML, eval), an attacker who can inject cookie values achieves DOM XSS. Look for code that reads document.cookie and passes the result to a sink.

Step 4.4: postMessage Handlers
Look for window.addEventListener('message', ...) handlers that process event.data without origin validation. If the handler passes event.data to a sink like innerHTML or eval, a malicious page can send a crafted message to trigger XSS.

Manual test: Open the target in one tab. Open about:blank in another tab. In the about:blank console, run:

javascript
window.open('https://target.com').postMessage('<img src=x onerror=alert(1)>', '*')
Watch the target tab for execution.

Step 4.5: Fragment-Based Routing
Many modern applications read location.hash for client-side routing. Manually test:

text
https://target.com/#<img src=x onerror=alert(1)>
https://target.com/#/route/<img src=x onerror=alert(1)>
https://target.com/page#javascript:alert(1)
Watch the DOM for injection.

Phase 5: Manual Exploitation & Validation
Step 5.1: Minimal Proof of Concept
Once you have a bypass, prove execution with the minimum necessary:

html
<script>alert(document.domain)</script>
or for DOM contexts:

html
<img src=x onerror=alert(document.domain)>
Never use payloads designed to steal credentials, sessions, or private data. The PoC proves execution. Impact assessment is separate.

Step 5.2: Victim Path Verification
Answer these before reporting:

Can another user trigger this? (Self-XSS is not a vulnerability.)

Does exploitation require user interaction?

Is the affected asset in scope?

Who can be affected? (Admin, moderator, regular user?)

If the answer to the first question is no, the finding is self-XSS and is not reportable unless you can chain it to a realistic victim path.

Step 5.3: False Positive Elimination
Reject findings where:

Input is safely encoded

Payload exists only inside comments

JavaScript is inert

CSP reliably prevents execution

Execution only occurs in the attacker's own browser

Exploitation requires impossible conditions

Step 5.4: Manual Headless Confirmation
Open the payload URL in a fresh browser profile with no extensions and no cookies. Open DevTools → Console. Reload the page. If an alert fires, or if the console shows your injected JS running, you have confirmed execution. Screenshot the console and the alert dialog.

If the alert does not fire, check the DevTools → Console for CSP violations or parsing errors. Each error tells you which layer failed and what to fix.

Phase 6: Manual Reporting
Report Structure
text
## Title
[Vulnerability type] in [component] allows [impact]

## Summary
2–4 sentences explaining the vulnerability.

## Affected Endpoint
URL, method, parameter, authentication state.

## Technical Details
Source → transformations → sink → parser context.
Why sanitization fails. Why the browser executes.

## Reproduction
Deterministic, numbered steps. Copy-paste URLs.

## Proof of Concept
Minimal harmless payload. Screenshot of the alert in a clean browser profile.

## Impact
Who is affected. What actions an attacker can perform.

## Remediation
Context-aware output encoding. Framework-specific fixes.
Quick Reference: Bypass Class Priority
Priority	Class	Success Indicator
1	Content-Type confusion	Backend parses body, WAF does not inspect
2	Encoding stacks	Browser decodes to executable syntax
3	Event handler alternatives	Handler fires in browser
4	SVG injection	SVG tag executes handler
5	Case variation / keyword splitting	Filter matches literal, HTML parses variant
6	HTTP/2 SPCA	Structure-only manipulation passes payload
7	HTTP Parameter Pollution	WAF inspects first value, backend uses last
8	Ghost Bits (Java)	Unicode passes WAF, Java truncates to ASCII
9	Newline-split	Signature sees broken token, browser reassembles
Manual Workflow Loop
For every promising input, repeat:

text
DISCOVER       — walk the page, read the JS, map the input
REFLECT        — submit canary, find where it lands
CLASSIFY       — identify context (HTML / attr / JS / URL / CSS)
TRACE          — follow the data from source to sink by reading code
ENCODE         — determine which decoder runs at the reflection point
FILTER         — identify what the WAF blocks vs. what the backend accepts
TEST           — submit controlled variations, one at a time
VERIFY         — open in clean browser, confirm execution
VICTIM         — verify another user can be affected
ELIMINATE      — reject false positives
REPORT         — write minimal, deterministic, reproducible report
Do not skip stages. Do not spray payloads. Submit one variation at a time and observe the exact response before moving on.

Research Papers & References
WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls (ACSAC 2025) — 1,207 bypasses across 5 WAFs via content-type confusion and multipart boundary manipulation

SPCA: Stream Parser Confusion Attack for Web Application Firewall Evasion in HTTP/2 (ACM Web Conference 2026) — 89%+ bypass rate via RFC-compliant stream priority manipulation, payload-agnostic

WAF Manis: Break the Wall from Bottom (IEEE S&P 2024) — 311 protocol-level evasions across 14 WAFs and 20 frameworks

Ghost Bits (Black Hat Asia 2026) — Java Unicode truncation allows ASCII payload reconstruction after WAF inspection

HTTP Parameter Pollution (PayloadPlayground 2026) — WAF bypass via split payloads across duplicate keys

CVE-2026-26961 — Rack multipart boundary parsing ambiguity allows WAF bypass

oncontentvisibilityautostatechange bypass (April 2026) — Cloudflare WAF bypass via CSS Containment API event handler

