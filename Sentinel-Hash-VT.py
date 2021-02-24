import requests
import json
import sys
from virustotal_python import Virustotal


banner = """

Azure Sentinel Alert Entities - VirusTotal Scanner 

Usage: python3 Sentinel-Hash-VT.py <System ALERT ID>

"""

print (banner)

# Add the rquired fields
Azure_AD_Tenant = "Azure_AD_Tenant_HERE"
Client_ID = "Client_ID_HERE"
Client_Secret = "Client_Secret_HERE"
ResourceGroup = "ResourceGroup_HERE"
Workspace = "Workspace_HERE"
Subscription = "Subscription_ID"
VT_API_KEY = "VirusTotal_Community_API_KEY_HERE "
SystemAlertId = str(sys.argv[1])


# Get the Access Token

Url = "https://login.microsoftonline.com/"+Azure_AD_Tenant+"/oauth2/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
payload='grant_type=client_credentials&client_id='+ Client_ID+'&resource=https%3A%2F%2Fmanagement.azure.com&client_secret='+Client_Secret
response = requests.post(Url, headers=headers, data=payload).json()
Access_Token = response["access_token"]
print("[+] Access Token Received Successfully")

# Get Alert details 
Url2= "https://management.azure.com/subscriptions/"+Subscription+"/resourceGroups/"+ResourceGroup+"/providers/Microsoft.OperationalInsights/workspaces/"+Workspace+"/api/query?api-version=2020-08-01"
payl2 = "\n \"query\": \"SecurityAlert | where SystemAlertId == \'"+SystemAlertId+"\'\"\n"
payload2="{"+payl2+"}"
Auth = 'Bearer '+Access_Token
headers2 = {
  'Authorization': Auth ,
  'Content-Type': 'text/plain'
}

response2 = requests.post(Url2, headers=headers2, data=payload2).json()
print("[+] Incident Details were received Successfully")

#Entities loading
Entities = response2["Tables"][0]["Rows"][0][21] 
Parsed_Entities = json.loads(Entities)
print("[+] Entities were received Successfully")

for i in range(len(Parsed_Entities)):
    if "Value" in Parsed_Entities[i]: 
        hash =  Parsed_Entities[i]["Value"]


vtotal = Virustotal(API_KEY=VT_API_KEY, API_VERSION="v3")

"""
Public API constraints and restrictions

The Public API is limited to 500 requests per day and a rate of 4 requests per minute.
The Public API must not be used in commercial products or services.
The Public API must not be used in business workflows that do not contribute new files.

"""

VT_resp = vtotal.request(f"files/{hash}").json()
results = VT_resp["data"]["attributes"]["last_analysis_results"]
magic = VT_resp["data"]["attributes"]["magic"]
print("[+] The File Magic is: "+magic)
for key, value in results.items():
    print("[+] "+value["engine_name"]+" - The scan result is: "+str(value["result"]))
