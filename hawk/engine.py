"""Execute declared capabilities with typed outcomes and injected I/O."""
from dataclasses import dataclass, field
import ipaddress
import os
import re
from urllib.parse import quote, urljoin, urlsplit
import dns.resolver
from .catalog import CATALOG
from .inputs import normalize, jwt_parts, origin
from .network import Gateway, LookupProblem
from .webpage import PATHS, extract

@dataclass
class Finding:
    state: str
    data: object = field(default_factory=dict)
    message: str = ''
    retry_origin: str = ''

class Engine:
    def __init__(self, gateway=None, credentials=None, resolver=None):
        self.gateway = gateway or Gateway()
        self.credentials = os.environ if credentials is None else credentials
        self.resolver = resolver

    def run(self, module, raw):
        if module not in CATALOG:
            raise LookupProblem('Capability is not in the bundled catalog.')
        target = normalize(module.kind, raw)
        token = self.credentials.get(module.credential, '') if module.credential else ''
        if module.credential and not token:
            raise LookupProblem(f'Missing {module.credential}. Set it in your private configuration and restart.')
        action = module.action
        if action == 'jwt':
            return Finding('Decoded, not verified', jwt_parts(target))
        if action == 'dns':
            return self.dns(target)
        if module.kind == 'website':
            return self.website(action, target)
        encoded = quote(target, safe='')
        headers = {}; params = {}
        if action == 'doh':
            url = 'https://dns.google/resolve'; params = {'name': target, 'type': 'A'}
        elif action == 'ip':
            url = 'https://ipwho.is/' + encoded
        elif action == 'archive':
            url = 'https://web.archive.org/cdx/search/cdx'
            params = {'url': target+'/*', 'output': 'json', 'limit': 50, 'collapse': 'urlkey'}
        elif action == 'ct':
            url = 'https://crt.sh/'; params = {'q': '%.'+target, 'output': 'json'}
        elif action == 'censys':
            url = 'https://api.platform.censys.io/v3/global/asset/host/' + encoded
            headers = {'Authorization': 'Bearer '+token, 'Accept': 'application/vnd.censys.api.v3.host.v1+json'}
        elif action == 'shodan':
            url = 'https://api.shodan.io/shodan/host/' + encoded; params = {'key': token}
        elif action == 'vt':
            try:
                ipaddress.ip_address(target); kind = 'ip_addresses'
            except ValueError:
                kind = 'domains'
            url = 'https://www.virustotal.com/api/v3/' + kind + '/' + encoded
            headers = {'x-apikey': token}
        elif action == 'otx':
            try:
                kind = 'IPv' + str(ipaddress.ip_address(target).version)
            except ValueError:
                kind = 'file' if re.fullmatch(r'[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}', target) else 'domain'
            url = 'https://otx.alienvault.com/api/v1/indicators/' + kind + '/' + encoded + '/general'
            headers = {'X-OTX-API-KEY': token}
        else:
            raise LookupProblem('Unsupported capability.')
        data = self.gateway.json(url, headers=headers, params=params)
        if isinstance(data, dict) and (data.get('success') is False or (action == 'doh' and data.get('Status') not in (None, 0))):
            return Finding('Provider could not complete lookup', data)
        return Finding('No records returned' if data in ([], {}) else 'Completed', data,
                       'Provider associations are observations, not a safety or maliciousness verdict.')

    def dns(self, target):
        resolver = self.resolver or dns.resolver.Resolver()
        output = {}; errors = []
        for label, name, rrtype in [(r, target, r) for r in ('A','AAAA','MX','NS','TXT','CNAME','SOA','CAA')] + [('DMARC', '_dmarc.'+target, 'TXT')]:
            try:
                output[label] = [answer.to_text() for answer in resolver.resolve(name, rrtype, lifetime=3, search=False)]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                output[label] = []
            except dns.exception.DNSException:
                output[label] = 'Query failed'; errors.append(label)
        output['SPF'] = [v for v in output['TXT'] if 'v=spf1' in v.lower()] if isinstance(output['TXT'], list) else 'TXT query unavailable'
        return Finding('Partial DNS response' if errors else 'Completed', output,
                       'Failed record types: '+', '.join(errors) if errors else 'Empty record sets do not establish safety.')

    def website(self, action, target):
        path = PATHS.get(action, '/')
        reply = self.gateway.fetch(target + path)
        if not 200 <= reply.code < 300:
            destination = urljoin(target + path, next((v for k,v in reply.headers.items() if k.lower() == 'location'), ''))
            retry = ''
            if 300 <= reply.code < 400:
                try:
                    a, b = urlsplit(target), urlsplit(destination)
                    if b.path in {'', '/', path} and b.scheme == 'https' and a.hostname.removeprefix('www.') == (b.hostname or '').removeprefix('www.') and not b.query and not b.fragment:
                        candidate = origin(b.scheme+'://'+b.netloc)
                        if candidate != target:
                            retry = candidate
                except ValueError:
                    pass
            return Finding('Not analyzed', {'HTTP status': reply.code, 'Destination': destination if 300 <= reply.code < 400 else ''},
                           'The page was not analyzed. Redirects require a separate explicit request; access denials are not bypassed.', retry)
        return Finding('Completed', {'HTTP status': reply.code, **extract(action, reply)},
                       'One response inspected. References were not fetched and forms were not submitted.')
