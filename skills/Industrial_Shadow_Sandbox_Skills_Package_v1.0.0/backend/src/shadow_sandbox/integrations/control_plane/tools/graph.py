def query_causal_graph(application, actor, graph_id: str):
    return application.resources.get(actor, "causal_graph", graph_id).as_dict()
