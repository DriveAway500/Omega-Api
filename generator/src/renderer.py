from parser import parse_routes, load_json_file


def render_file(output_path):
    pass

def renderer():
    data = load_json_file()
    routes = parse_routes(data)
    return routes