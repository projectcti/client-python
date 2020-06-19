# coding: utf-8

import json
from pycti import OpenCTIApiClient

# Variables
api_url = "https://projectcti.com"
api_token = "815dd7b7-1b96-4cb1-9b0e-27d9a3d88fdb"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the intrusion set Kimsuky
intrusion_set = opencti_api_client.intrusion_set.read(
    filters=[{"key": "name", "values": ["Kimsuky"]}]
)

# Create the bundle
bundle = opencti_api_client.stix2.export_entity(
    "indicator", "f37e5125-74c2-4faa-91ed-e7d228c76f37", "full"
)
json_bundle = json.dumps(bundle, indent=4)

# Write the bundle
f = open("Kimsuky.json", "w")
f.write(json_bundle)
f.close()
