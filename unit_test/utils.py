import re


# From https://stackoverflow.com/questions/14693701/
# how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
def escape_ansi(line):
    ansi_escape = re.compile(
        r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]", re.MULTILINE
    )
    return ansi_escape.sub("", line)
