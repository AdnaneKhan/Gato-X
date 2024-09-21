from gatox.cli import cli
import sys


def entry():
    sys.exit(cli.cli(sys.argv[1:]))


if __name__ == "__main__":
    sys.exit(cli.cli(sys.argv[1:]))
