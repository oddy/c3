from . import commandline

# --- setup.py entry_point for "c3" command goes via here ---
def main():
    commandline.CommandlineMain()

# --- python -m c3  commands go via here ---
if __name__ == "__main__":
    commandline.CommandlineMain()
