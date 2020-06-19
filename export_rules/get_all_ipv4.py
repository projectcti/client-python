# coding: utf-8
from pycti import OpenCTIApiClient
import base64
import os
from pathlib import Path

filename = Path('Indicators.yara')
filename.touch(exist_ok=True)

# Variables
api_url = "https://demo.opencti.io"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get all reports using the pagination
custom_attributes = """
    id
    indicator_pattern
    created
"""
number_rule = 0
final_indicators = []
data = opencti_api_client.Instruction.list(
    filters=[{"key": "pattern_type", "values": ["yara"]}],
    first=50, customAttributes=custom_attributes, withPagination=True
)
final_indicators = final_indicators + data["entities"]

try:
    while data["pagination"]["hasNextPage"]: # and number_rule <3:
        after = data["pagination"]["endCursor"]
        print("Listing indicators after " + str(base64.b64decode(after)))
        data = opencti_api_client.indicator.list(
            filters=[{"key": "pattern_type", "values": ["yara"]}],
            first=50, after=after, customAttributes=custom_attributes, withPagination=True
        )
        final_indicators = final_indicators + data["entities"]
        for indicator in final_indicators:
            number_rule += 1
            rule = "/*\nRule: " + str(number_rule) + "\n[" + indicator["created"] + "] \n*/\n" + indicator["indicator_pattern"] + "\n"
            with open("Indicators.yara", "a", encoding="utf-8") as f:
                f.write(str(rule))

        final_indicators = []

    print("Write rule successfully")
except:
    print("Error")