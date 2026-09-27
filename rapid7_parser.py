"""Rapid7 category articles -> real Excel .xls, saved in Downloads.

Setup: py -m pip install --user requests beautifulsoup4 python-dateutil xlwt
Run:   py rapid7_parser.py
Optional: py rapid7_parser.py --pages 3 --since 2026-09-01

Default scope is all articles linked on the category landing page, including
featured articles. --pages follows explicit Next links when available; it does
not promise a complete historical archive or JavaScript-only Load More results.
Each run re-reads articles, so newly added CVEs in older articles are captured.
Exit codes: 0 complete, 1 fatal/no report, 2 report saved with omissions.
"""

import argparse
from datetime import date, datetime
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup
from dateutil.parser import parse as parse_date
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import xlwt

CATEGORY = 'https://www.rapid7.com/blog/category/vulnerabilities-and-exploits/'
CVE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)
NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CVSS_METRICS = (('cvssMetricV40', '4.0'), ('cvssMetricV31', '3.1'),
                ('cvssMetricV30', '3.0'), ('cvssMetricV2', '2.0'))


def affected_technologies(configurations):
    """Summarize vulnerable CPE match criteria, preserving version bounds."""
    products = set()

    def visit(node):
        for match in node.get('cpeMatch', []):
            if not match.get('vulnerable'):
                continue
            parts = match.get('criteria', '').split(':')
            if len(parts) < 6 or parts[:2] != ['cpe', '2.3']:
                continue
            vendor, product, version = parts[3:6]
            if vendor in ('*', '-') or product in ('*', '-'):
                continue
            label = f'{vendor.replace("_", " ")} / {product.replace("_", " ")}'
            bounds = [f'{key}: {match[key]}' for key in (
                'versionStartIncluding', 'versionStartExcluding',
                'versionEndIncluding', 'versionEndExcluding') if match.get(key)]
            if version not in ('*', '-'):
                bounds.insert(0, f'version {version}')
            if bounds:
                label += ' (' + '; '.join(bounds) + ')'
            products.add(label)
        for child in node.get('children', []):
            visit(child)

    for configuration in configurations or []:
        for node in configuration.get('nodes', []):
            visit(node)
    return '; '.join(sorted(products)) if products else 'Not listed in NVD'


def nvd_details(payload, cve_id):
    records = [entry['cve'] for entry in payload.get('vulnerabilities', [])
               if entry.get('cve', {}).get('id', '').upper() == cve_id.upper()]
    if not records:
        return {'score': 'Not found in NVD', 'technology': 'Not found in NVD'}
    record = records[0]
    metrics = record.get('metrics', {})
    score = 'Not scored in NVD'
    for field, version in CVSS_METRICS:
        candidates = metrics.get(field, [])
        if candidates:
            # Prefer NVD's own assessment when both NVD and CNA scores exist.
            selected = next((m for m in candidates if m.get('source') == 'nvd@nist.gov'), candidates[0])
            data = selected.get('cvssData', {})
            if data.get('baseScore') is not None:
                score = f"{data['baseScore']} (CVSS {version}, {selected.get('source', 'source unknown')})"
                break
    return {'score': score, 'technology': affected_technologies(record.get('configurations'))}


class NVDClient:
    """Per-run CVE cache and courteous request pacing for the NVD API."""
    def __init__(self, session, api_key=None):
        self.session = session
        self.api_key = api_key
        self.cache = {}
        self.last_request = 0.0

    def lookup(self, cve_id):
        if cve_id in self.cache:
            return self.cache[cve_id]
        interval = 0.7 if self.api_key else 6.5
        delay = interval - (time.monotonic() - self.last_request)
        if delay > 0:
            time.sleep(delay)
        headers = {'apiKey': self.api_key} if self.api_key else {}
        try:
            self.last_request = time.monotonic()
            response = self.session.get(NVD_API, params={'cveId': cve_id},
                                        headers=headers, timeout=(15, 45))
            response.raise_for_status()
            details = nvd_details(response.json(), cve_id)
        except (requests.RequestException, ValueError) as exc:
            raise ValueError(f'NVD lookup for {cve_id} failed: {exc}') from exc
        self.cache[cve_id] = details
        return details


def enrich_cves(cves, nvd, warnings):
    details = {}
    for cve in cves:
        try:
            details[cve] = nvd.lookup(cve)
        except ValueError as exc:
            warnings.append(str(exc))
            details[cve] = {'score': 'NVD lookup failed', 'technology': 'NVD lookup failed'}
    return details


def downloads_folder():
    # Honor a redirected Windows Downloads folder (including OneDrive).
    if os.name == 'nt':
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders') as key:
                value, _ = winreg.QueryValueEx(key, '{374DE290-123F-4565-9164-39C4925E467B}')
            return Path(os.path.expandvars(value))
        except OSError:
            pass
    return Path.home() / 'Downloads'


def canonical_url(href, base):
    p = urlsplit(urljoin(base, href))
    if p.scheme not in ('http', 'https') or p.hostname not in ('www.rapid7.com', 'rapid7.com'):
        return None
    return urlunsplit(('https', 'www.rapid7.com', p.path, p.query, ''))


def get_page(session, url):
    response = session.get(url, timeout=(15, 60))
    response.raise_for_status()
    return BeautifulSoup(response.content, 'html.parser')


def article_links(soup, base):
    return list(dict.fromkeys(u for a in soup.select('a[href]')
        if (u := canonical_url(a['href'], base))
        and re.match(r'^/blog/(?:post/|\d{4}/\d{2}/\d{2}/)', urlsplit(u).path)))


def next_page(soup, base):
    for a in soup.select('a[href], link[rel="next"][href]'):
        label = (a.get_text(' ', strip=True) + ' ' + a.get('aria-label', '')).lower()
        if 'next' in a.get('rel', []) or re.search(r'\bnext\b', label):
            u = canonical_url(a['href'], base)
            if u and urlsplit(u).path.startswith(urlsplit(CATEGORY).path):
                return u
    return None


def json_objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from json_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from json_objects(child)


def extract_article(soup):
    structured = []
    for script in soup.select('script[type="application/ld+json"]'):
        try:
            for obj in json_objects(json.loads(script.get_text())):
                kinds = obj.get('@type', [])
                if isinstance(kinds, str):
                    kinds = [kinds]
                if any(k in ('Article', 'NewsArticle', 'BlogPosting', 'TechArticle') for k in kinds):
                    structured.append(obj)
        except (ValueError, TypeError):
            continue
    heading = soup.find('h1')
    title = heading.get_text(' ', strip=True) if heading else ''
    if not title:
        title = next((o['headline'] for o in structured if o.get('headline')), '')
    if not title:
        meta = soup.select_one('meta[property="og:title"]')
        title = meta.get('content', '') if meta else ''
    if not title:
        raise ValueError('No article headline found; page structure may have changed')

    dates = [o['datePublished'] for o in structured if o.get('datePublished')]
    for selector in ('meta[property="article:published_time"]',
                     'meta[name="date"]', '[itemprop="datePublished"]',
                     'time.published', 'time[datetime]'):
        for el in soup.select(selector):
            if 'modified' not in str(el.get('class', '')).lower():
                dates.append(el.get('content') or el.get('datetime') or el.get_text(' ', strip=True))
    published = None
    for raw in dates:
        try:
            published = parse_date(str(raw)).date()
            break
        except (ValueError, OverflowError):
            pass

    body = soup.select_one('[itemprop="articleBody"], .article-content, .post-content, .blog-post-content, .blog-content, .article-body, .post-body, .gh-content')
    if body is None:
        body = soup.find('article') or soup.find('main')
    body_text = next((o['articleBody'] for o in structured if o.get('articleBody')), '')
    if body is not None:
        # Work on a copy; exclude navigation and recommended article widgets.
        copy = BeautifulSoup(str(body), 'html.parser')
        for el in copy.select('script, style, nav, aside, footer, .related-posts, .related-articles, .recommended-posts'):
            el.decompose()
        body_text += '\n' + copy.get_text('\n', strip=True)
        body_text += '\n' + '\n'.join(a['href'] for a in copy.select('a[href]'))
    if not body_text.strip():
        raise ValueError('No article body found; update the body CSS selectors')
    # Rapid7's article footer is not part of the article itself.
    body_text = re.split(r'\n(?:Article tags|Related articles|Related posts|Share this article)\n', body_text, maxsplit=1, flags=re.I)[0]
    if published is None:
        initial = re.search(r'([A-Z][a-z]+\s+\d{1,2},\s+\d{4}):\s*Initial publication', body_text)
        if initial:
            published = parse_date(initial.group(1)).date()
    cves = sorted(set(CVE.findall(title.upper() + '\n' + body_text.upper())),
                  key=lambda c: tuple(map(int, c.split('-')[1:])))
    return published, title, cves


def write_excel(rows, output_dir):
    if len(rows) > 65535:
        raise ValueError('.xls supports only 65,535 data rows per sheet')
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / datetime.now().strftime('Rapid7Parser_%d%m%y_%H_%M.xls')
    book = xlwt.Workbook(encoding='utf-8')
    sheet = book.add_sheet('Rapid7 CVEs')
    header = xlwt.easyxf('font: bold on, colour white; pattern: pattern solid, fore_colour dark_blue; alignment: wrap on;')
    body = xlwt.easyxf('alignment: wrap on, vert top;')
    date_style = xlwt.easyxf('alignment: vert top;', num_format_str='DD-MMM-YYYY')
    columns = (('Published date', 19), ('News heading', 90), ('All CVEs', 75),
               ('NVD CVSS score by CVE', 75), ('Affected technology by CVE (NVD)', 110))
    for col, (name, width) in enumerate(columns):
        sheet.write(0, col, name, header)
        sheet.col(col).width = width * 256
    sheet.set_panes_frozen(True)
    sheet.set_horz_split_pos(1)
    for r, (published, title, cves, details) in enumerate(rows, 1):
        value = ', '.join(cves)
        scores = '\n'.join(f'{cve}: {details[cve]["score"]}' for cve in cves)
        technologies = '\n'.join(f'{cve}: {details[cve]["technology"]}' for cve in cves)
        if any(len(text) > 32767 for text in (title, value, scores, technologies)):
            raise ValueError('Article exceeds Excel cell character limit; nothing truncated')
        sheet.write(r, 0, datetime.combine(published, datetime.min.time()) if published else 'Date unavailable', date_style)
        # xlwt writes strings as text, never as executable Excel formulas.
        sheet.write(r, 1, title, body)
        sheet.write(r, 2, value, body)
        sheet.write(r, 3, scores, body)
        sheet.write(r, 4, technologies, body)
    # Exclusive creation prevents accidentally overwriting a run in the same minute.
    with path.open('xb') as handle:
        book.save(handle)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pages', type=int, default=1, help='Maximum category pages; default 1')
    parser.add_argument('--since', type=date.fromisoformat, help='Inclusive publication date YYYY-MM-DD')
    parser.add_argument('--output-dir', type=Path, default=downloads_folder())
    args = parser.parse_args()
    if args.pages < 1:
        parser.error('--pages must be at least 1')
    session = requests.Session()
    session.headers['User-Agent'] = 'Rapid7CVEParser/1.0 (personal vulnerability news review)'
    session.mount('https://', HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504], allowed_methods=['GET'])))
    nvd = NVDClient(session, os.environ.get('NVD_API_KEY'))
    rows, problems, urls, seen = [], [], [], set()
    page = CATEGORY
    for _ in range(args.pages):
        if not page or page in seen:
            break
        seen.add(page)
        print('Category:', page)
        try:
            soup = get_page(session, page)
            links = article_links(soup, page)
            if not links:
                raise ValueError('No article links found; possible site change or access restriction')
            urls.extend(links)
            page = next_page(soup, page)
        except (requests.RequestException, ValueError) as exc:
            problems.append(f'{page}: {exc}')
            break
        time.sleep(1)
    if args.pages > 1 and not page:
        print('No further explicit Next link found; JavaScript-only archives are not included.')
    for url in dict.fromkeys(urls):
        print('Reading:', url)
        try:
            published, title, cves = extract_article(get_page(session, url))
            if not cves:
                continue
            if published is None:
                problems.append(f'{url}: publication date unavailable' + ('; excluded by --since' if args.since else ''))
                if args.since:
                    continue
            if args.since and published < args.since:
                continue
            details = enrich_cves(cves, nvd, problems)
            rows.append((published, title, cves, details))
        except (requests.RequestException, ValueError) as exc:
            problems.append(f'{url}: {exc}')
        finally:
            time.sleep(1)
    for problem in problems:
        print('WARNING:', problem, file=sys.stderr)
    if not rows:
        print('No matching articles. No Excel file created.', file=sys.stderr)
        return 1 if problems else 0
    rows.sort(key=lambda row: row[0] or date.min, reverse=True)
    output = write_excel(rows, args.output_dir.expanduser())
    print(f'Saved {len(rows)} articles: {output}')
    if problems:
        print('PARTIAL RESULT: review the warnings above.', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
