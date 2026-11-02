from hawk.presentation import explain

def test_vt_preserves_zero_and_distinguishes_classifications():
    summary,data=explain('vt',{'data':{'attributes':{'reputation':0,'last_analysis_stats':{'malicious':2,'suspicious':2,'harmless':52,'undetected':36}}}})
    assert '2 engines reported malicious' in summary
    assert data['Community reputation']==0
    assert data['Engine classifications']['Undetected']==36

def test_otx_preserves_zero_and_assessments():
    summary,data=explain('otx',{'pulse_info':{'count':0},'validation':[{'message':'Known False Positive'}]})
    assert 'does not establish safety' in summary
    assert data['Report count']==0
    assert 'Known False Positive' in data['Provider assessments']
