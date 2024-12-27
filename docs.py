"""
Generate docs for API 
"""

import json
import yaml
from authapi.api.app import create_app

schema = create_app().openapi()


def _extract_tags(schema: dict):
    """
    Get endpoint tags
    """
    tags = set()

    # Extract tags from paths
    for _, methods in schema.get("paths", {}).items():
        for _, details in methods.items():
            if "tags" in details:
                for tag in details["tags"]:
                    tags.add(tag)

    return tags


def update_schema_with_tags(schema: dict):
    """add endpoint tags to top level"""
    existing_tags = {tag["name"] for tag in schema.get("tags", [])}
    path_tags = _extract_tags(schema)

    # Add missing tags to the top level
    for tag in path_tags:
        if tag not in existing_tags:
            if "tags" not in schema:
                schema["tags"] = []
            schema["tags"].append(
                {"name": tag, "description": f"Operations related to {tag}"}
            )

    return schema


updated_schema = update_schema_with_tags(schema)


with open("./docs/openapi.yaml", "w", encoding="utf-8") as f:
    f.write(yaml.dump(updated_schema))

with open("./docs/openapi.json", "w", encoding="utf-8") as f:
    f.write(json.dumps(updated_schema))
