# Rapid7 CVE Reader

A Python web application that scans Rapid7's Vulnerabilities & Exploits category,
reads each linked article, and exports publication date, headline and all unique
CVE IDs to a genuine .xls workbook. No API key is needed.

## Run on Windows

1. Extract the ZIP. Open the rapid7_web folder in File Explorer.
2. Type cmd in File Explorer's address bar and press Enter.
3. Run these commands, one at a time (no virtual-environment activation needed):

```cmd
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app.py
```

4. Open http://127.0.0.1:8000 and select **Scan Rapid7**.
5. Wait for completion, optionally choose a publication date, then Download .xls.
6. Keep the command window open while using the app. Ctrl+C stops it.

The local address works only on your computer. It is not an internet sharing URL.
Using the virtual environment's exact Python path avoids the IDLE/pip interpreter
mismatch encountered with the original script. Do not run this app in IDLE.

## Publish a URL others can use (Render)

You need a GitHub account and a Render account. This package has not been deployed.

1. Create a GitHub repository. Upload the CONTENTS of rapid7_web so app.py,
   requirements.txt and render.yaml are at the repository root. Include static/
   and templates/. Do not upload .venv or __pycache__.
2. In Render, choose New > Web Service and connect this repository.
3. Choose Python 3 as the runtime.
4. Build command: `pip install -r requirements.txt`
5. Start command: `python app.py`
6. Add environment variable `HOST` with value `0.0.0.0`.
   Render supplies PORT automatically. Choose an instance plan and review its cost.
7. Deploy. Once deployment succeeds, copy the HTTPS URL Render provides and share it.

Alternatively, use Render's Blueprint workflow with the included render.yaml.
Official guide: https://render.com/docs/deploy-flask
Web service documentation: https://render.com/docs/web-services

This app uses Waitress as its production web server, including on Windows.
Run ONE process and ONE instance: scan progress and results are kept in memory.
Do not add multiple Gunicorn workers or scale replicas without moving job state to
a shared database/queue. Hosting restarts or sleeping instances clear the results;
run Scan again. Long scans use a background thread so HTTP requests remain short.

## What users get

- Scan progress and a table with links to original Rapid7 articles.
- Publication date filter; undated articles are excluded when a filter is active.
- Exactly three Excel columns: Published date / News heading / All CVEs.
- Filename Rapid7Parser_DDMMYY_HH_MM.xls using the downloading browser's local time.
- A browser download, saved according to that person's browser settings (normally
  Downloads). Websites cannot silently force a local Downloads-folder path.
- Warnings for failed articles and missing dates; a partial report can be exported.

## Scope and operation

The scan covers article links present in the category's first-page HTML, including
featured posts. It does not crawl the entire historical archive, follow arbitrary
URLs, expand JavaScript-only archives or validate CVEs against NVD. CVEs are unique
per article; the same CVE can appear in several article rows. The source parser
prioritizes datePublished metadata, not last-modified dates. Site layout changes
may require updating rapid7_parser.py.

All visitors share one current scan/result. At most one scan runs at a time and
new scans are limited to once every five minutes per process. Date filters apply
only to each viewer. A new scan retains the previous table while it runs but
downloads are disabled until it finishes. No user files, passwords or private
company data are collected. There is no login: anyone with the hosted URL can
view public results and start a scan within the shared limit. For an internal-only
deployment, put it behind your organization's approved authentication gateway.

The host must be able to access www.rapid7.com via HTTPS. A hosting-provider block,
rate limit or source layout change is surfaced as an error/warning. Reports are
generated in temporary folders and served as downloads; they are not retained.

## Files

- app.py: web routes, background scan and Excel download
- rapid7_parser.py: reusable extraction/export functions and original CLI
- templates/index.html: interface
- static/: styling, browser behavior and favicon
- requirements.txt: dependencies
- render.yaml: deployment configuration

## Checks

`python -m unittest discover -s tests` runs a fixture-based web workflow check.
It does not contact Rapid7 or claim that every live article has been validated.
