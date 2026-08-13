import csv


def read_csv(handle):
    yield from csv.DictReader(handle)
