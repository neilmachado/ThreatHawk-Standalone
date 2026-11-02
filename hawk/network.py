"""One bounded HTTP request. Exceptions never carry credentials to the UI."""
from dataclasses import dataclass
import json
import time
import requests

class LookupProblem(Exception):
    pass

@dataclass
class Reply:
    code: int
    headers: dict
    body: str

class Gateway:
    limit = 2_000_000

    def fetch(self, url, *, headers=None, params=None):
        try:
            started = time.monotonic()
            with requests.Session() as client:
                client.trust_env = False
                with client.get(url, headers=headers, params=params, stream=True,
                                timeout=(5, 15), allow_redirects=False, verify=True) as response:
                    if not 200 <= response.status_code < 300:
                        return Reply(response.status_code, dict(response.headers), '')
                    chunks = bytearray()
                    for chunk in response.iter_content(32768):
                        chunks.extend(chunk)
                        if len(chunks) > self.limit:
                            raise LookupProblem('Response exceeded the 2 MB limit; no analysis performed.')
                        if time.monotonic() - started > 30:
                            raise LookupProblem('Response exceeded the time budget; try later.')
                    return Reply(response.status_code, dict(response.headers), chunks.decode(response.encoding or 'utf-8', errors='replace'))
        except requests.exceptions.SSLError:
            raise LookupProblem('TLS verification failed. Check the destination certificate; verification remains enabled.') from None
        except requests.exceptions.Timeout:
            raise LookupProblem('Request timed out. Try again later.') from None
        except requests.exceptions.RequestException:
            raise LookupProblem('Network request failed. Check connectivity and try later.') from None

    def json(self, url, **options):
        response = self.fetch(url, **options)
        if response.code != 200:
            explanation = {
                401: 'Authentication rejected; check your key.',
                403: 'Access denied; check provider permissions or subscription membership.',
                404: 'No provider record found for this input.',
                429: 'Rate limit reached; wait before retrying.',
            }.get(response.code, 'Provider unavailable or redirect returned; no automatic retry.')
            raise LookupProblem(f'HTTP {response.code}: {explanation}')
        try:
            return json.loads(response.body)
        except (ValueError, RecursionError):
            raise LookupProblem('Provider returned invalid JSON; try later.') from None
