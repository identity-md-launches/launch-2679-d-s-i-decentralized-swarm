import sys

from .cli import main

if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["scan"]:
        args = args[1:]
    main(args)
