import json


def read_jsonl(handle):
    for line in handle:
        yield json.loads(line)
