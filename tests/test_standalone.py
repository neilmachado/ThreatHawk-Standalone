from io import StringIO
import json
from unittest.mock import Mock
import pytest
from rich.console import Console
import dns.resolver
from hawk.catalog import CATALOG, HINTS
from hawk.engine import Engine
from hawk.inputs import normalize
from hawk.network import Gateway, Reply, LookupProblem
from hawk.ui import Terminal

HTML = '''<html><head><meta name="generator" content="Sample"></head><body><!-- sample -->
<a href="https://www.linkedin.com/company/sample">social</a><script src="https://cdn.example.com/app.js"></script>
<form method="post" action="/submit"><input name="user" value="do-not-display" autocomplete="off"></form>
<iframe src="https://embed.example.com"></iframe><img width="1" src="pixel.gif">recaptcha</body></html>'''


def setup_engine():
    gateway=Mock()
    gateway.json.return_value={'record':'sample'}
    gateway.fetch.return_value=Reply(200,{'Server':'Sample','Set-Cookie':'sid=hidden; Secure; HttpOnly'},HTML)
    resolver=Mock()
    resolver.resolve.return_value=[Mock(to_text=lambda:'sample')]
    return Engine(gateway,{m.credential:'test-key' for m in CATALOG if m.credential},resolver)

@pytest.mark.parametrize('module', CATALOG, ids=lambda m:m.action)
def test_every_capability_dispatches_once_or_runs_offline(module):
    engine=setup_engine()
    if module.action=='sitemap':
        engine.gateway.fetch.return_value.body='<urlset><url><loc>https://example.com/</loc></url></urlset>'
    result=engine.run(module,HINTS[module.kind][1])
    assert result.state in {'Completed','Decoded, not verified'}
    if module.kind=='website':
        assert engine.gateway.fetch.call_count==1
        assert engine.gateway.json.call_count==0
    elif module.action in {'dns','jwt'}:
        assert engine.gateway.mock_calls==[]
        if module.action=='dns': assert engine.resolver.resolve.call_count==9
    else:
        assert engine.gateway.json.call_count==1

@pytest.mark.parametrize('kind,text', [('ip','example.com'),('domain','8.8.8.8'),('domain','me@example.com'),('website','https://example.com/path'),('website','http://127.0.0.1'),('website','https://user:pass@example.com'),('jwt','invalid'),('website','https://example.com:8443')])
def test_reject_invalid_targets(kind,text):
    with pytest.raises(ValueError): normalize(kind,text)

@pytest.mark.parametrize('action,expected', [('social','linkedin'),('technology','cdn.example.com'),('forms','Autocomplete'),('captcha','recaptcha'),('comments','sample'),('pixels','pixel.gif'),('embeds','embed.example.com'),('cookies','HttpOnly')])
def test_observations_and_no_form_or_cookie_values(action,expected):
    engine=setup_engine(); module=next(m for m in CATALOG if m.action==action)
    serialized=json.dumps(engine.run(module,'example.com').data)
    assert expected in serialized
    assert 'do-not-display' not in serialized and 'hidden' not in serialized

@pytest.mark.parametrize('status',[301,403,404,429,500])
def test_website_status_never_claims_empty_success(status):
    engine=setup_engine();engine.gateway.fetch.return_value=Reply(status,{'Location':'https://www.example.com/'},'')
    result=engine.run(CATALOG[8],'example.com')
    assert result.state=='Not analyzed'
    assert engine.gateway.fetch.call_count==1
    assert bool(result.retry_origin)==(status==301)

@pytest.mark.parametrize('target',['https://evil.test/','http://www.example.com/','https://user:pass@www.example.com/','https://www.example.com/path','https://www.example.com/?secret=x'])
def test_redirect_shortcut_restricted(target):
    engine=setup_engine();engine.gateway.fetch.return_value=Reply(301,{'Location':target},'')
    assert not engine.run(CATALOG[8],'example.com').retry_origin


def test_missing_key_never_calls_network():
    engine=setup_engine();engine.credentials={}
    with pytest.raises(LookupProblem,match='Missing'):engine.run(CATALOG[14],'8.8.8.8')
    assert engine.gateway.mock_calls==[]


def test_dns_partial_and_no_answer_are_different():
    engine=setup_engine()
    engine.resolver.resolve.side_effect=[dns.resolver.NoAnswer(),dns.resolver.LifetimeTimeout()]+[[]]*7
    result=engine.run(CATALOG[1],'example.com')
    assert result.state=='Partial DNS response'
    assert result.data['A']==[] and result.data['AAAA']=='Query failed'


def test_literal_rendering_redacts_keys():
    engine=setup_engine();out=StringIO()
    terminal=Terminal(engine,Console(file=out,width=100))
    terminal.say('[bold]plain[/bold] test-key\x1b[2J')
    assert '[bold]plain[/bold]' in out.getvalue()
    assert 'test-key' not in out.getvalue() and '\x1b' not in out.getvalue()


def test_contextual_flow_and_explicit_redirect():
    engine=setup_engine()
    engine.gateway.fetch.side_effect=[Reply(301,{'Location':'https://www.example.com/'},''),Reply(200,{},HTML)]
    out=StringIO();answers=iter(['2','09','example.com','r','q'])
    Terminal(engine,Console(file=out,width=100),lambda _:next(answers)).run()
    assert out.getvalue().count('1. View modules')==1
    assert [c.args[0] for c in engine.gateway.fetch.call_args_list]==['https://example.com/','https://www.example.com/']

@pytest.mark.parametrize('status',[401,403,404,429,500])
def test_http_errors_are_credential_safe(status):
    gateway=Gateway();gateway.fetch=Mock(return_value=Reply(status,{},'SECRET'))
    with pytest.raises(LookupProblem) as caught:gateway.json('https://example.com')
    assert str(status) in str(caught.value) and 'SECRET' not in str(caught.value)


def test_bad_json_is_safe():
    gateway=Gateway();gateway.fetch=Mock(return_value=Reply(200,{},'SECRET'))
    with pytest.raises(LookupProblem,match='invalid JSON'):gateway.json('https://example.com')


def test_transport_bounds_and_no_redirects(monkeypatch):
    client=Mock();response=Mock(status_code=200,headers={},encoding='utf-8')
    response.iter_content.return_value=[b'hello']
    client.get.return_value.__enter__=Mock(return_value=response)
    client.get.return_value.__exit__=Mock(return_value=False)
    session=Mock();session.__enter__=Mock(return_value=client);session.__exit__=Mock(return_value=False)
    monkeypatch.setattr('hawk.network.requests.Session',lambda:session)
    assert Gateway().fetch('https://example.com').body=='hello'
    assert client.get.call_args.kwargs['allow_redirects'] is False
    assert client.get.call_args.kwargs['verify'] is True
    assert client.trust_env is False
    response.iter_content.return_value=[b'x'*2_000_001]
    with pytest.raises(LookupProblem,match='2 MB'):Gateway().fetch('https://example.com')

@pytest.mark.parametrize('action,value,path,header', [
 ('censys','8.8.8.8','/v3/global/asset/host/8.8.8.8','Authorization'),
 ('shodan','8.8.8.8','/shodan/host/8.8.8.8',''),
 ('vt','example.com','/api/v3/domains/example.com','x-apikey'),
 ('vt','8.8.8.8','/api/v3/ip_addresses/8.8.8.8','x-apikey'),
 ('otx','8.8.8.8','/api/v1/indicators/IPv4/8.8.8.8/general','X-OTX-API-KEY'),
 ('otx','example.com','/api/v1/indicators/domain/example.com/general','X-OTX-API-KEY'),
 ('otx','a'*64,'/api/v1/indicators/file/'+'a'*64+'/general','X-OTX-API-KEY'),
])
def test_provider_contract_paths_and_auth(action,value,path,header):
    engine=setup_engine();engine.run(next(m for m in CATALOG if m.action==action),value)
    call=engine.gateway.json.call_args
    assert call.args[0].endswith(path)
    if header: assert 'test-key' in call.kwargs['headers'][header]
    else: assert call.kwargs['params']['key']=='test-key'

@pytest.mark.parametrize('xml',['<!DOCTYPE urlset><urlset/>','<html/>','<urlset>'])
def test_bad_sitemap_never_claims_success(xml):
    engine=setup_engine();engine.gateway.fetch.return_value.body=xml
    with pytest.raises(LookupProblem):engine.run(CATALOG[6],'example.com')


def test_empty_jwt_signature_is_decoded_but_never_verified():
    engine=setup_engine()
    result=engine.run(CATALOG[20],HINTS['jwt'][1])
    assert result.state=='Decoded, not verified' and result.data['Claims']['sub']=='demo'
    assert not engine.gateway.mock_calls


def test_display_limits_and_unknown_error_redaction():
    from hawk.engine import Finding
    out=StringIO();engine=setup_engine();terminal=Terminal(engine,Console(file=out,width=120))
    terminal.results(Finding('Completed',{'long':'x'*5000,'many':list(range(600))}))
    assert 'display shortened' in out.getvalue() and 'Further rows omitted' in out.getvalue()
    out=StringIO();engine.run=Mock(side_effect=RuntimeError('do-not-leak-token'))
    answers=iter(['2','01','example.com','q'])
    Terminal(engine,Console(file=out,width=120),lambda _:next(answers)).run()
    assert 'do-not-leak-token' not in out.getvalue()
    assert 'Unexpected processing failure' in out.getvalue()
