from .client import ReadonlySubscriptionClient


class SubscriptionManager:
    def __init__(self, client: ReadonlySubscriptionClient) -> None:
        self.client = client
        self.nodes: tuple[str, ...] = ()

    def rebuild(self, node_ids, callback) -> None:
        self.nodes = tuple(node_ids)
        self.client.subscribe(self.nodes, callback)
