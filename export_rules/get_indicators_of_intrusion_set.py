# coding: utf-8

from pycti import OpenCTIApiClient
import base64
import os
import json
from pathlib import Path

class Rule:
    action = 'drop'
    direction = '->'
    disabled = ''
    dst = 'any'
    dst_port = 'any'
    options = ''
    content = ''
    fast_pattern = ''
    flow = ''
    metadata = ''
    msg = ''
    reference = ''
    rev = ''
    sid = ''
    protocol = ''
    src = 'any'
    src_port = 'any'

def createRule(type_pattern, pattern):
    rule = Rule()
    if "url:value" in type_pattern:
        rule.msg = rule.action + ' [' + type_pattern + '] ' + pattern

        rule.protocol = "tcp"
        rule.content = pattern.split(":")[1][2:]
    # elif ""
    if rule.msg != '': rule.msg = ' msg:"'+ rule.msg + '";'
    if rule.content != '': rule.content = ' content:"'+ rule.content + '";'

    final_rule = rule.action + ' ' + rule.protocol + ' ' + rule.src + ' ' + rule.src_port + ' ' + rule.direction + ' ' + rule.dst + ' ' + rule.dst_port + ' (' + rule.msg + ' ' + rule.content + ' )'
    return final_rule
print(createRule("url:value", "https://www.zeites.com/wp-includes/Text/Diff/Engine/native/expres.php?op=2"))
exit()
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

for stix_relation in stix_relations:
    id_pattern = stix_relation["to"]["id"]

    final_indicators = []
    indicator = opencti_api_client.indicator.read( 
        id = id_pattern
    )

    indicator_pattern = str(indicator["indicator_pattern"])
    type_pattern = indicator_pattern.split(" ")[0][1:]
    pattern = indicator_pattern.split("'")[1]

    # print(type_pattern + " : " + pattern)
    rule = createRule(type_pattern, pattern)
    print(rule)

    # fileName = nameIntrusionSet + ".rules"
    # f = open(fileName, "w", encoding="utf-8")

    # f.write(pattern)
    # f.write("\n")
    # f.close()