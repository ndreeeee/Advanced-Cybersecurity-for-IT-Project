import requests
import urllib3
import json

urllib3.disable_warnings()

search_query = '''| makeresults 
| eval user="alice.medico" 
| eval software="chrome_115" 
| eval device="tpm_enclave_88" 
| eval network="10.0.0.15" 
| eval action="update" 
| eval resource="cartelle_cliniche" 
| apply trust_model'''

data = {
    'search': search_query,
    'output_mode': 'json',
    'exec_mode': 'oneshot'
}

import os
splunk_user = os.getenv("SPLUNK_USER", "admin")
splunk_password = os.getenv("SPLUNK_PASSWORD", "changeme")

resp = requests.post(
    'https://zta-splunk:8089/services/search/jobs', 
    auth=(splunk_user, splunk_password), 
    data=data, 
    verify=False
)

print('Status:', resp.status_code)
try:
    print('JSON:', json.dumps(resp.json(), indent=2))
except:
    print('Text:', resp.text)
