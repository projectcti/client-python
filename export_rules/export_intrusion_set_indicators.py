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

# Get all reports using the pagination
custom_attributes = """
    id
    indicator_pattern
    created
"""
# Create the bundle
data = opencti_api_client.indicator.list(
    customAttributes=custom_attributes, withPagination=True
)
final_indicators = data["entities"]
# json_bundle = json.dumps(data, indent=4)

# Write the bundle
f = open("Kimsuky_indicators.json", "w")
f.write(final_indicators)
f.close()
