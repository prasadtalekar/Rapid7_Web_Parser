import unittest
from datetime import date
from unittest.mock import patch
import app as web


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.client = web.app.test_client()
        web.state.update(status='idle', rows=[], warnings=[], completed=0, total=0, updated=None)

    def test_scan_results_and_excel_download(self):
        with patch.object(web, 'get_page', return_value=None), \
             patch.object(web, 'article_links', return_value=['https://www.rapid7.com/blog/post/test/']), \
             patch.object(web, 'extract_article', return_value=(date(2026,9,23), 'Example article', ['CVE-2026-94127'])), \
             patch.object(web, 'enrich_cves', return_value={'CVE-2026-94127': {'score': '8.8 (CVSS 3.1, nvd@nist.gov)', 'technology': 'acme / product (version 1.0)'}}), \
             patch.object(web.time, 'sleep'):
            web.scan()
        data = self.client.get('/api/results').get_json()
        self.assertEqual(data['status'], 'ready')
        self.assertEqual(data['rows'][0]['cves'], ['CVE-2026-94127'])
        self.assertEqual(data['rows'][0]['nvd']['CVE-2026-94127']['score'], '8.8 (CVSS 3.1, nvd@nist.gov)')
        self.assertEqual(data['rows'][0]['nvd']['CVE-2026-94127']['technology'], 'acme / product (version 1.0)')
        report = self.client.get('/download?stamp=260926_16_30')
        self.assertEqual(report.status_code, 200)
        self.assertTrue(report.data.startswith(bytes.fromhex('D0CF11E0A1B11AE1')))
        self.assertIn('Rapid7Parser_260926_16_30.xls', report.headers['Content-Disposition'])
        self.assertEqual(self.client.get('/download?since=2026-09-24').status_code,404)
        self.assertEqual(self.client.get('/download?since=invalid').status_code,400)

    def test_errors_and_scan_guards(self):
        self.assertEqual(self.client.get('/download').status_code,409)
        self.assertEqual(self.client.post('/api/scan').status_code,403)
        with patch.object(web, 'get_page', return_value=None), \
             patch.object(web, 'article_links', return_value=['https://www.rapid7.com/blog/post/test/']), \
             patch.object(web, 'extract_article', side_effect=ValueError('Missing body')), \
             patch.object(web.time, 'sleep'):
            web.scan()
        self.assertEqual(web.state['status'], 'partial')
        self.assertEqual(len(web.state['warnings']), 1)
        web.state['status']='running'
        self.assertEqual(self.client.post('/api/scan',headers={'X-Requested-With':'Rapid7Reader'}).status_code,202)

    def test_interface(self):
        page = self.client.get('/').data
        self.assertIn(b'Scan Rapid7',page)
        self.assertIn(b'NVD CVSS score by CVE',page)
        self.assertIn(b'Affected technology by CVE (NVD)',page)
        self.assertIn(b'colspan="5"',page)
        self.assertEqual(self.client.get('/static/app.js').status_code,200)


if __name__ == '__main__':
    unittest.main()
