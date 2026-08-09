from renderer import renderer, render_rsfile

def main():
    routes = renderer()
    print(routes)
    content = "// Generated Rust code for routes\n"
    render_rsfile(content)

if __name__ == "__main__":
    main()