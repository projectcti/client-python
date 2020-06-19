# coding: utf-8

from pycti import OpenCTIApiClient
import base64
import os
import json
from pathlib import Path

# Variables
api_url = "https://projectcti.com"
api_token = "815dd7b7-1b96-4cb1-9b0e-27d9a3d88fdb"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

nameIntrusionSet = "KIMSUKY"

intrusion_set = opencti_api_client.intrusion_set.read(
    filters=[{"key": "name", "values": [nameIntrusionSet]}]
)

stix_relations = opencti_api_client.stix_relation.list(
    fromId=intrusion_set["id"], toTypes=["Indicator"], inferred=True
)

print("Results: \n")
fileName = nameIntrusionSet + ".snort"
f = open(fileName, "w", encoding="utf-8")

for stix_relation in stix_relations:
    id_pattern = stix_relation["to"]["id"]

    final_indicators = []
    indicator = opencti_api_client.indicator.read( 
        id = id_pattern
    )

    print(str(indicator["indicator_pattern"]))
    f.write(str(indicator["indicator_pattern"]))
    f.write("\n")

f.close()