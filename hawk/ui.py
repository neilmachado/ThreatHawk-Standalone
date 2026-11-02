"""Contextual terminal workflow; rendering never interprets remote markup."""
import re
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from .catalog import CATALOG, HINTS
from .engine import Engine
from .network import LookupProblem

DISCLAIMER = '''⚠️ WARNING: LEGAL DISCLAIMER
This tool is intended for educational and ethical use only. The author is not liable for any illegal use or misuse of this tool. Users are solely responsible for their actions and must ensure they have explicit permission to scan the target systems.'''


def walk(data, location='Result', depth=0):
    if depth > 12:
        yield location, 'Further nesting omitted from display'
    elif isinstance(data, dict) and data:
        for key, value in data.items():
            yield from walk(value, str(key) if location == 'Result' else location+' / '+str(key), depth+1)
    elif isinstance(data, list) and data:
        for index, value in enumerate(data, 1):
            yield from walk(value, location+f' [{index}]', depth+1)
    else:
        value = 'No entries returned' if data in ([], {}) else 'Not supplied' if data is None or data == '' else str(data)
        yield location, value

class Terminal:
    def __init__(self, engine=None, console=None, read=input):
        self.engine = engine or Engine()
        self.console = console or Console()
        self.read = read
        self.selected = None

    def text(self, value):
        value = str(value)
        for item in CATALOG:
            secret = self.engine.credentials.get(item.credential, '')
            if secret:
                value = value.replace(secret, '[credential redacted]')
        return Text(re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', '', value))

    def say(self, value):
        self.console.print(self.text(value))

    def listing(self):
        table = Table(title='Choose a capability', header_style='bold cyan')
        for heading in ('No.', 'Module', 'Input', 'Source'):
            table.add_column(heading)
        for m in CATALOG:
            table.add_row(f'{m.number:02}', m.title, HINTS[m.kind][0], m.source)
        self.console.print(table)

    def details(self):
        m = self.selected
        label, example = HINTS[m.kind]
        key = 'Not required' if not m.credential else m.credential + (' — configured' if self.engine.credentials.get(m.credential) else ' — missing')
        self.console.print(Panel(self.text(f'{m.number:02} · {m.title}\nSource: {m.source}\nRequired input: {label}\nExample: {example}\nAPI key: {key}'), border_style='#ff6037'))
        if m.action == 'vt':
            self.say('VirusTotal documents that queried indicators may be scanned and added to its dataset. Do not query confidential indicators.')
        if m.kind == 'website':
            self.say('One page request only. Use a destination you are permitted to check.')

    def results(self, finding):
        self.say('Status: '+finding.state)
        table = Table(header_style='bold cyan', expand=True)
        table.add_column('Field', ratio=1, overflow='fold')
        table.add_column('Observation', ratio=2, overflow='fold')
        for count, (key, value) in enumerate(walk(finding.data)):
            if count >= 500:
                table.add_row('Display limit', 'Further rows omitted after 500 rows.')
                break
            if len(value) > 4000:
                value = value[:4000]+' … [display shortened]'
            table.add_row(self.text(key), self.text(value))
        self.console.print(table)
        if finding.message:
            self.say(finding.message)

    def session(self):
        self.details()
        redirect = ''
        while True:
            hint = f'; r to request {redirect}' if redirect else ''
            value = self.read(f'Input for {self.selected.title}{hint}; Enter for help; b home; q exit: ').strip()
            if value.lower() == 'q':
                return False
            if value.lower() == 'b':
                return True
            if not value:
                self.details(); continue
            if value.lower() == 'r' and redirect:
                value = redirect
            redirect = ''
            try:
                self.say('Source: '+self.selected.source)
                self.say('Running '+self.selected.title+'…')
                result = self.engine.run(self.selected, value)
                self.results(result)
                redirect = result.retry_origin
            except ValueError as error:
                self.say('Invalid input: '+str(error))
            except LookupProblem as error:
                self.say(str(error))
            except KeyboardInterrupt:
                self.say('Lookup cancelled. Enter another input or return home.')
            except Exception:
                self.say('Unexpected processing failure. No raw response or credentials were printed.')

    def run(self):
        self.console.print(Panel(self.text(DISCLAIMER), border_style='yellow'))
        self.say('THREATHAWK  1.0.0 · Standalone edition\nCreated and maintained by Neil Machado\n22 guided capabilities')
        try:
            while True:
                self.console.print(Panel('1. View modules\n2. Select module\n3. Run module\n4. Exit', title='ThreatHawk', border_style='#ff6037', expand=False))
                choice = self.read('Choose 1–4: ').strip()
                if choice == '4':
                    break
                if choice == '3' and self.selected:
                    if not self.session(): break
                elif choice in {'1', '2', '3'}:
                    self.listing()
                    while True:
                        number = self.read('Module number 01–22; b home; q exit: ').strip().lower()
                        if number == 'q': return
                        if number == 'b': break
                        if not number.isascii() or not number.isdigit() or not 1 <= int(number) <= len(CATALOG):
                            self.say('Choose a number from 01 through 22.'); continue
                        self.selected = CATALOG[int(number)-1]
                        if not self.session(): return
                        break
                else:
                    self.say('Choose one of the four home options.')
        except (EOFError, KeyboardInterrupt):
            pass
        finally:
            self.say('ThreatHawk closed.')


def main():
    Terminal().run()
