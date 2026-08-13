def slice_key(labels: dict[str, str]) -> str:
    return "/".join(f"{key}:{labels[key]}" for key in sorted(labels))
