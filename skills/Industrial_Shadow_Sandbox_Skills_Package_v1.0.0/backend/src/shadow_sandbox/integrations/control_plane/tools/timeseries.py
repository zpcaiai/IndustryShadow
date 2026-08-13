def query_signal_window(
    application, actor, run_id: str, signal_key: str, start=None, end=None, limit: int = 1000
):
    return application.signal_events(actor, run_id, signal_key, start, end, limit)
