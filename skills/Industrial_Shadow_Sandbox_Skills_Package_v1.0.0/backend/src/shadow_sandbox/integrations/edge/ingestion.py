from shadow_sandbox.application import ApplicationService


def ingest(application: ApplicationService, actor, batch):
    return application.ingest_edge_batch(actor, batch)
