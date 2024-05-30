"""
Generate docs for API 
"""

import json
import yaml
from authapi.api.app import create_app

schema = create_app().openapi()

with open("./docs/openapi.yaml", "w", encoding="utf-8") as f:
    f.write(yaml.dump(schema))

with open("./docs/openapi.json", "w", encoding="utf-8") as f:
    f.write(json.dumps(schema))
