from pathlib import Path

from parser import parse_routes, load_json_file

PATH = Path(__file__).resolve().parent.parent.parent
FILE_PATH = PATH / "generated" / "routes.rs"


def render_rsfile(content):
    """Renders the content to a Rust file."""

    # Generate the parent directory if it doesn't exist
    FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    

def renderer():
    data = load_json_file()
    routes = parse_routes(data)
    return routes