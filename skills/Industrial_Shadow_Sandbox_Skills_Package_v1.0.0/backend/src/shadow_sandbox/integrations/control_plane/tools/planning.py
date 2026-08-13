def propose_check_plan(application, actor, run_id: str, request=None):
    return application.create_check_plan(actor, run_id, request or {})
