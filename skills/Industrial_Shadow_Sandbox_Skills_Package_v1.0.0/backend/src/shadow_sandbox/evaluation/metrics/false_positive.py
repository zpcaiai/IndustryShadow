def false_positive_metrics(normals):
    return {"false_positive_rate": sum(item.detected for item in normals) / max(len(normals), 1)}
