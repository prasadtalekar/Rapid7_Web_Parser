"""Single-process Flask application. Public data only; no persistent accounts."""
from datetime import date, datetime, timezone
from io import BytesIO
import os
from pathlib import Path
import tempfile
import threading
import time

from flask import Flask, jsonify, render_template, request, send_file
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rapid7_parser import (CATEGORY, NVDClient, article_links, enrich_cves,
                           extract_article, get_page, write_excel)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 4096
lock = threading.Lock()
state = dict(status='idle', completed=0, total=0, rows=[], warnings=[], updated=None)
last_started = 0.0
COOLDOWN = 300


def scan():
    try:
        with requests.Session() as session:
            session.headers['User-Agent'] = 'Rapid7CVEReader/1.0 (public news review)'
            session.mount('https://', HTTPAdapter(max_retries=Retry(total=2,
                backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])))
            nvd = NVDClient(session, os.environ.get('NVD_API_KEY'))
            urls = article_links(get_page(session, CATEGORY), CATEGORY)
            if not urls:
                raise ValueError('No article links found. The site may have changed or blocked access.')
            # Fixed source only, bounded work; there is no arbitrary-URL fetch API.
            if len(urls) > 100:
                raise ValueError('Unexpectedly many article links. Review the category parser.')
            with lock:
                state['total'] = len(urls)
            rows, warnings = [], []
            for index, url in enumerate(urls):
                try:
                    published, title, cves = extract_article(get_page(session, url))
                    if cves:
                        details = enrich_cves(cves, nvd, warnings)
                        rows.append(dict(date=published.isoformat() if published else None,
                                         title=title, cves=cves, nvd=details, url=url))
                        if not published:
                            warnings.append(f'Publication date unavailable: {title}')
                except (requests.RequestException, ValueError) as exc:
                    warnings.append(f'Could not read {url}: {exc}')
                with lock:
                    state['completed'] = index + 1
                time.sleep(0.5)
            rows.sort(key=lambda r: r['date'] or '', reverse=True)
            with lock:
                state.update(status='partial' if warnings else 'ready', rows=rows,
                             warnings=warnings, updated=datetime.now(timezone.utc).isoformat())
    except Exception:
        app.logger.exception('Rapid7 scan failed')
        with lock:
            state.update(status='error', warnings=['Unable to scan Rapid7. Please try again later.'])


@app.get('/')
def index():
    return render_template('index.html')


@app.post('/api/scan')
def start_scan():
    global last_started
    # Require a same-origin script request; no permissive CORS configuration.
    if request.headers.get('X-Requested-With') != 'Rapid7Reader':
        return jsonify(error='Invalid request'), 403
    with lock:
        if state['status'] == 'running':
            return jsonify(status='running'), 202
        remaining = max(0, int(COOLDOWN - (time.monotonic() - last_started)))
        if remaining:
            return jsonify(error=f'Please wait {remaining} seconds before rescanning.'), 429
        last_started = time.monotonic()
        state.update(status='running', completed=0, total=0, warnings=[])
        threading.Thread(target=scan, daemon=True).start()
    return jsonify(status='running'), 202


@app.get('/api/results')
def results():
    with lock:
        return jsonify(state)


@app.get('/download')
def download():
    since = request.args.get('since', '')
    try:
        cutoff = date.fromisoformat(since) if since else None
    except ValueError:
        return 'Invalid date. Use YYYY-MM-DD.', 400
    with lock:
        rows = list(state['rows'])
        status = state['status']
    if status not in ('ready', 'partial'):
        return 'Finish a scan before downloading.', 409
    selected = [(date.fromisoformat(r['date']) if r['date'] else None, r['title'], r['cves'], r['nvd'])
                for r in rows if not cutoff or (r['date'] and r['date'] >= cutoff.isoformat())]
    if not selected:
        return 'No matching CVE articles to download.', 404
    with tempfile.TemporaryDirectory() as directory:
        report = write_excel(selected, Path(directory))
        data = report.read_bytes()
    # Browser sends local clock for the requested filename; validate strictly.
    stamp = request.args.get('stamp', '')
    try:
        filename = datetime.strptime(stamp, '%d%m%y_%H_%M').strftime('Rapid7Parser_%d%m%y_%H_%M.xls')
    except ValueError:
        filename = report.name
    return send_file(BytesIO(data), mimetype='application/vnd.ms-excel',
                     as_attachment=True, download_name=filename, max_age=0)


@app.after_request
def headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if not request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'no-store'
    return response


if __name__ == '__main__':
    from waitress import serve
    print('Rapid7 CVE Reader: http://127.0.0.1:8000', flush=True)
    serve(app, host=os.environ.get('HOST', '127.0.0.1'),
          port=int(os.environ.get('PORT', '8000')), threads=8)
