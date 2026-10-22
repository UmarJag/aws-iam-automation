import json

json_File = "deny_delete_policy.json"
print("Startin AWS IAM Json policy")

try:
    with open(json_File, "r") as file_pointer:
        policy_date = json.load(file_pointer)
    print("SUCCESS! JSON file successfuly loaded.")

except FileNotFoundError:
    print(f"FILE NOT FOUND ERROR. The file '{json_File}' was not found")
    exit()
except json.JSONDecodeError as json_error:
    print(f"JSON FORMAT ERROR: A syntex or format issue was found in json file: '{json_File}'. ")
    print(f"Details: {json_error}")
    exit()

version_control = policy_date['Version']
print(f"IAM SCHEMA Version: {version_control}")
print("Policy Statements detected.")

for index, rules_block in enumerate(policy_date["Statement"]):
    print(f"\n[Statement # {index + 1} ]")    
    print(F"Rule Enforcement: {rules_block['Effect']}")
    print(F"Target operation: {rules_block['Action']}")
    print(F"Target Resource: {rules_block['Resource']}")


    is_vulnerable = False

    if rules_block['Action'] == "*":
        print("⚠️ VULNERABILITY ALERT: Full Action Wildcard Detected!")
        is_vulnerable = True

    if rules_block['Resource'] == "*":
        print("⚠️ VULNERABILITY ALERT. FUll resource wildCard detected ")
        is_vulnerable = True

    if not is_vulnerable:
        print("✅ Parameters are scoped correctly.")

    print("----------------------------------------")
