import csv


def load_csv(file_path):
    with open(file_path, "r", encoding="utf-8") as logs:
        return [log for log in csv.reader(logs)]