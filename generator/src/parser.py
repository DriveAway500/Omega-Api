import json
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
API_FILE_PATH = BASE_DIR / "api.json"


def load_json_file():
    """Parses a JSON file and returns the data as a Python object.

    Returns:
        dict: The parsed JSON data as a Python dictionary, or empty dict if
        invalid.
    """
    if not API_FILE_PATH.exists():
        print(f"Error: File '{API_FILE_PATH.name}' not found.")
        return {}

    if API_FILE_PATH.stat().st_size == 0:
        print(
            f"Error: The file '{API_FILE_PATH.name}' is completely empty (0"
            " bytes)."
        )
        return {}

    try:
        with open(API_FILE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not data:
            print(
                f"Error: The JSON content in '{API_FILE_PATH.name}' is empty."
            )
            return {}

        return data

    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format in '{API_FILE_PATH.name}': {e.msg}")
        return {}


@dataclass
class Route:
    name: str
    method: str
    path: str
    response_type: str


def parse_routes(data):
    """Parses the routes from the given data."""
    routes_data = data.get("routes", [])
    routes = []

    for route_data in routes_data:
        try:
            route = Route(
                name=route_data["name"],
                method=route_data["method"],
                path=route_data["path"],
                response_type=route_data["response_type"],
            )
            routes.append(route)
        except KeyError as e:
            print(f"Error: Missing key {e} in route data: {route_data}")

    return routes


# def print_routes(routes):
#     for r in routes:
#         print(f"[{r.method}] {r.path} - {r.name} ({r.response_type})")


# def main():
#     data = load_json_file()
#     routes = parse_routes(data)
#     print(f"Parsed {len(routes)} routes:")
#     print_routes(routes)


# if __name__ == "__main__":
#     main()