from shadow_sandbox.common import DomainError


def validate(nodes, edges) -> None:
    ids = {node.id for node in nodes}
    if len(ids) != len(tuple(nodes)):
        raise DomainError("GRAPH_DUPLICATE_NODE", "graph node IDs must be unique")
    if any(edge.source not in ids or edge.target not in ids for edge in edges):
        raise DomainError("GRAPH_BROKEN_EDGE", "graph edge endpoint missing")
