"""Readable summaries over existing responses; no extra requests."""
from datetime import datetime, timezone


def simplify(value):
    if isinstance(value, dict):
        return {str(k).replace('_',' ').capitalize(): simplify(v) for k,v in value.items() if v not in (None,'',[],{})}
    if isinstance(value,list): return [simplify(v) for v in value]
    return value


def explain(action, data):
    if action == 'archive' and isinstance(data,list) and data and isinstance(data[0],list):
        return f'{max(0,len(data)-1)} archive captures returned. Archived pages were not fetched.', [dict(zip(data[0],row)) for row in data[1:] if isinstance(row,list)]
    if action == 'ct' and isinstance(data,list):
        return f'{len(data)} certificate records returned. Certificates show recorded names, not current ownership or safety.', [simplify({k:r.get(k) for k in ('name_value','issuer_name','not_before','not_after')}) for r in data if isinstance(r,dict)]
    if not isinstance(data,dict):
        return f'{len(data)} records returned.' if isinstance(data,list) else 'Response received.', simplify(data)
    if action=='vt':
        attrs=data.get('data',{}).get('attributes',{})
        stats=attrs.get('last_analysis_stats',{})
        summary=(f"{stats.get('malicious','Unknown')} engines reported malicious; {stats.get('suspicious','unknown')} reported suspicious. These are provider classifications, not a definitive verdict.")
        findings={'Engine classifications':stats,'Community reputation':attrs.get('reputation'), 'Network owner':attrs.get('as_owner'),'Country':attrs.get('country')}
        findings['Flagged engines']={k:{'classification':v.get('category'),'reason':v.get('result')} for k,v in attrs.get('last_analysis_results',{}).items() if v.get('category') in ('malicious','suspicious')}
        date=attrs.get('last_analysis_date')
        if isinstance(date,(int,float)):
            try: findings['Last analysis (UTC)']=datetime.fromtimestamp(date,timezone.utc).strftime('%Y-%m-%d %H:%M')
            except (ValueError,OverflowError,OSError):pass
        return summary,simplify(findings)
    if action=='otx':
        pulse=data.get('pulse_info',{})
        count=pulse.get('count','Unknown')
        return f'{count} OTX threat-report associations. An association is context to investigate; zero associations does not establish safety.', simplify({'Indicator':data.get('indicator'),'Network':data.get('asn'),'Country':data.get('country_name'),'Report count':count,'Provider assessments':[v.get('message') or v.get('name') for v in data.get('validation',[]) if isinstance(v,dict)],'Reports':[{'Title':p.get('name'),'Updated':p.get('modified')} for p in pulse.get('pulses',[]) if isinstance(p,dict)]})
    if action in ('shodan','censys'):
        host=data.get('result',{}).get('resource',data)
        return 'Previously observed host information from the provider. Listed services may have changed since observation.',simplify({k:host.get(k) for k in ('ip','ip_str','org','asn','autonomous_system','location','country_name','hostnames','ports','services','last_updated_at','last_update','vulns')})
    explanations={
      'dns':'DNS records describe addresses, mail routing and domain policies. Empty records can be normal.',
      'doh':'DNS answers returned by Google. Answer type 1 is an IPv4 address; TTL is cache lifetime in seconds.',
      'ip':'Approximate network ownership and location. Geolocation does not identify a person or exact address.',
      'technology':'Technology clues and referenced hosts found in this page. They may not describe the entire application.',
      'cookies':'Cookie settings from this response. Secure limits transport to HTTPS; HttpOnly prevents script access; SameSite controls cross-site sending.',
      'headers':'Response headers and browser security policies. An absent header alone does not prove a vulnerability.',
      'forms':'Forms and input settings found in the page. No forms were submitted.',
      'robots':'Crawler instructions published by the site. These rules are not access controls.',
      'security':'Published security contact and disclosure information.',
      'sitemap':'Published page or child-sitemap locations. These locations were not visited.',
      'social':'Social profile links in the downloaded HTML. JavaScript-loaded links may be missing.',
      'comments':'HTML comments visible in the downloaded page.',
      'captcha':'CAPTCHA product names found in page markup; their presence does not prove enforcement.',
      'embeds':'Embedded content referenced by this page. The references were not loaded.',
      'pixels':'Images with a one-pixel dimension. This is a tracking hint, not proof.',
      'jwt':'Decoded token contents only. The signature and claims have not been verified.',
    }
    return explanations.get(action,'Returned observations; missing information is not proof of safety.'),simplify(data)
