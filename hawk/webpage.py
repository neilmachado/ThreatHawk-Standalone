"""Extract observations from a single response, never follow discovered links."""
from http.cookies import SimpleCookie, CookieError
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from bs4 import BeautifulSoup, Comment
from .network import LookupProblem

PATHS = {'robots': '/robots.txt', 'sitemap': '/sitemap.xml', 'security': '/.well-known/security.txt'}
POLICIES = ('Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options',
            'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy')
SOCIAL = {'facebook.com', 'instagram.com', 'linkedin.com', 'youtube.com', 'twitter.com', 'x.com', 'tiktok.com'}


def reference(value):
    try:
        return (urlsplit(value).hostname or '').lower().removeprefix('www.')
    except ValueError:
        return ''


def extract(action, reply):
    headers = {key.lower(): value for key, value in reply.headers.items()}
    if action in {'robots', 'security'}:
        return {'Document': reply.body}
    if action == 'headers':
        return {'Response headers': reply.headers,
                'Policy headers': {key: headers.get(key.lower(), 'Absent in this response') for key in POLICIES}}
    if action == 'cookies':
        cookies = SimpleCookie()
        try:
            cookies.load(headers.get('set-cookie', ''))
        except CookieError:
            raise LookupProblem('Cookie header could not be parsed.') from None
        return {'Cookies': [{'Name': key, 'Secure': bool(item['secure']), 'HttpOnly': bool(item['httponly']),
                             'SameSite': item['samesite'], 'Path': item['path']} for key, item in cookies.items()],
                'Coverage': 'Response cookies only. Combined Set-Cookie headers can lose detail; values are omitted.'}
    if action == 'sitemap':
        if '<!DOCTYPE' in reply.body.upper() or '<!ENTITY' in reply.body.upper():
            raise LookupProblem('XML entity and DTD declarations are not supported.')
        try:
            tree = ET.fromstring(reply.body)
        except ET.ParseError:
            raise LookupProblem('The sitemap response is not valid XML.') from None
        if tree.tag.rsplit('}', 1)[-1] not in {'sitemapindex', 'urlset'}:
            raise LookupProblem('XML is not a sitemap index or URL set.')
        return {'Locations': [node.text.strip() for node in tree.iter() if node.tag.rsplit('}', 1)[-1] == 'loc' and node.text],
                'Coverage': 'Locations are listed only; child sitemaps are not fetched.'}
    html = BeautifulSoup(reply.body, 'html.parser')
    if action == 'social':
        return {'Social links': sorted({a['href'] for a in html.select('a[href]') if reference(a['href']) in SOCIAL}),
                'Coverage': 'Static HTML only; absence does not establish that no accounts exist.'}
    if action == 'technology':
        return {'Server': headers.get('server'), 'Powered by': headers.get('x-powered-by'),
                'Generators': [m.get('content', '') for m in html.select('meta[name="generator"]')],
                'Referenced hosts': sorted({reference(n.get('src') or n.get('href') or '') for n in html.select('script[src],link[href],iframe[src]')} - {''})}
    if action == 'forms':
        return {'Forms': [{'Method': f.get('method', 'GET'), 'Action': f.get('action', ''),
                           'Autocomplete': f.get('autocomplete', ''),
                           'Fields': [{'Name': n.get('name', ''), 'Type': n.get('type', n.name), 'Autocomplete': n.get('autocomplete', '')}
                                      for n in f.select('input,textarea,select')]} for f in html.find_all('form')]}
    if action == 'comments':
        return {'Comments': [str(c) for c in html.find_all(string=lambda x: isinstance(x, Comment))]}
    if action == 'captcha':
        return {'CAPTCHA hints': [name for name in ('recaptcha', 'hcaptcha', 'turnstile') if name in reply.body.lower()]}
    if action == 'embeds':
        return {'Objects': [{'Element': n.name, 'Reference': n.get('src') or n.get('data') or ''} for n in html.select('iframe,object,embed')]}
    if action == 'pixels':
        return {'Pixel hints': [{'Source': n.get('src', ''), 'Width': n.get('width', ''), 'Height': n.get('height', '')}
                                for n in html.find_all('img') if '1' in (n.get('width'), n.get('height'))],
                'Interpretation': 'A one-pixel dimension alone does not prove tracking.'}
    raise LookupProblem('Unsupported website operation.')
