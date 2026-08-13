def get_evidence(application, actor, run_id: str):
    return application.resources.get(actor, "evidence_set", f"evidence:{run_id}").as_dict()
