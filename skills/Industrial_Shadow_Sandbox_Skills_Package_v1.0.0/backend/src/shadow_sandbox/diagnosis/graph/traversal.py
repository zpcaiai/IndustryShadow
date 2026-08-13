def bounded_upstream(edges, start: str, max_depth: int = 4) -> tuple[tuple[str, ...], ...]:
    paths = []
    frontier = [(start,)]
    for _ in range(max_depth):
        next_frontier = []
        for path in frontier:
            for edge in edges:
                if edge.target == path[-1] and edge.source not in path:
                    new = path + (edge.source,)
                    paths.append(new)
                    next_frontier.append(new)
        frontier = next_frontier
    return tuple(paths)
