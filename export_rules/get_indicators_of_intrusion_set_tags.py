import os
import json
import time
import base64
from pathlib import Path
from datetime import datetime
from pycti import OpenCTIApiClient

class Rule:
    def __init__(self):
        self.action = 'drop'
        self.protocol = 'tcp'
        self.src = 'any'
        self.src_port = 'any'
        self.direction = '->'
        self.dst = 'any'
        self.dst_port = 'any'
        self.sid = str(sid)
        self.msg = ''
        self.content = ''
        self.disabled = ''
        self.options = ''
        self.fast_pattern = ''
        self.flow = ''
        self.metadata = ''
        self.reference = ''
        self.rev = ''
        self.protected_content = ''
        self.hash = ''

    def final_rule(self):
        final_rule = self.action + ' ' + self.protocol + ' ' + self.src + ' ' + self.src_port + ' ' + self.direction + ' ' + self.dst + ' ' + self.dst_port

        final_rule += ' ('

        if self.sid != '': final_rule += ' sid:"'+ self.sid + '";'
        if self.msg != '': final_rule += ' msg:"'+ self.msg + '";'
        if self.content != '': final_rule += ' content:"'+ self.content + '";'
        if self.disabled != '': final_rule += ' disabled:"'+ self.disabled + '";'
        if self.options != '': final_rule += ' options:"'+ self.options + '";'
        if self.fast_pattern != '': final_rule += ' fast_pattern:"'+ self.fast_pattern + '";'
        if self.flow != '': final_rule += ' flow:"'+ self.flow + '";'
        if self.metadata != '': final_rule += ' metadata:"'+ self.metadata + '";'
        if self.reference != '': final_rule += ' reference:"'+ self.reference + '";'
        if self.rev != '': final_rule += ' rev:"'+ self.rev + '";'
        if self.protected_content != '': final_rule += ' protected_content:"'+ self.protected_content + '";'
        if self.hash != '': final_rule += ' hash:'+ self.hash + ';'

        final_rule += ')'

        return final_rule

def createRule(type_pattern, pattern):
    rule = Rule()

    if "url:value" in type_pattern:
        rule.content = pattern
        rule.msg = "url malware detected: " + pattern
    elif "hash" in type_pattern:
        rule.hash = type_pattern.split(".")[1].lower()
        rule.protected_content = pattern
        rule.msg = "file malware detected: " + pattern
    elif "domain-name:value" in type_pattern:
        rule.content = pattern
        rule.msg = "domain malware detected: " + pattern

    return rule.final_rule()

# print(createRule("url:value", "https://www.zeites.com/wp-includes/Text/Diff/Engine/native/expres.php?op=2"))
# print(createRule("hash:md5", "ef87dbd48fed4bcaf02cfc9e8c534344"))
# exit()
# Variables

api_url = "https://projectcti.com"
api_token = "815dd7b7-1b96-4cb1-9b0e-27d9a3d88fdb"

print("Connecting to " + api_url + " ...")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

print("Server connected!")
print("Getting patterns ...")

# Get all reports using the pagination
custom_attributes = """
    id
    name
    tags {
        edges {
            node {
                value
            }
        }
    }  
"""
while True:
    print("Colecting tags: University")
    final_intrusion_set_tags = []
    data = opencti_api_client.intrusion_set.list(
        first=50, customAttributes=custom_attributes, withPagination=True
    )
    final_intrusion_set_tags = final_intrusion_set_tags + data["entities"]

    while data["pagination"]["hasNextPage"]:
        after = data["pagination"]["endCursor"]
        print("Listing tags after " + str(base64.b64decode(after)))
        data = opencti_api_client.intrusion_set.list(
            first=50, after=after, customAttributes=custom_attributes, withPagination=True
        )
        final_intrusion_set_tags = final_intrusion_set_tags + data["entities"]

    # Print
    sid = 1000000
    fileName = "University.rules"
    f = open(fileName, "w", encoding="utf-8")
    f.write("#" + str(datetime.now()) + "\n")
    f.close()

    for intrusion_set in final_intrusion_set_tags:
        tag = intrusion_set["tags"]
        
        if tag != []:
            if str(tag[0]["value"]) == "University":
                # print(intrusion_set["id"])
                print("=============================================\n")
                print("Getting stix_relation of [" + intrusion_set["name"] + "]\n")

                stix_relations = opencti_api_client.stix_relation.list(
                    fromId=intrusion_set["id"], toTypes=["Indicator"], inferred=True
                )

                print("=============================================\n")
                print("Export rules from: [" + intrusion_set["name"] + "]\n")
                # exit()
                fileName = "University.rules"
                f = open(fileName, "a", encoding="utf-8")
                
                f.write("#================================================\n")
                f.write("# [" + intrusion_set["name"] + "]\n")
                f.write("#================================================\n")

                for stix_relation in stix_relations:
                    id_pattern = stix_relation["to"]["id"]

                    final_indicators = []
                    indicator = opencti_api_client.indicator.read( 
                        id = id_pattern
                    )
                    if str(indicator["pattern_type"]) != "stix":
                        continue
                    indicator_pattern = str(indicator["indicator_pattern"])

                    type_pattern = indicator_pattern.split(" ")[0][1:]
                    pattern = indicator_pattern.split("'")[1]
                    print(type_pattern + " : " + pattern)

                    rule = createRule(type_pattern, pattern)
                    print(" ===> Rule: " + rule)

                    sid+=1

                    f.write("# " + type_pattern + " : " + pattern + "\n")
                    f.write(rule + "\n")

                    # time.sleep(0.5)
                    # if sid > 1000005: exit()
                f.close()

    print("\nSuccessfully Export Rules with tags University!\n")

    print("Waiting update ...")
    time.sleep(1000)
