import re
import json

def clean_json_structure(data):
    # Convert JSON to a string with indentation
    json_str = json.dumps(data, indent=2)

    # Remove only the curly braces {}, square brackets [] and double quotes "
    cleaned_str = re.sub(r'[{}"\[\]]', '', json_str)

    return cleaned_str