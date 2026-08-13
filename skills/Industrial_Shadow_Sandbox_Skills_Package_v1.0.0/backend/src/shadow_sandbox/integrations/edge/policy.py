ALLOWED_OPERATIONS = frozenset(
    {"Browse", "Read", "CreateSubscription", "CreateMonitoredItems", "Publish"}
)


def is_allowed(operation: str) -> bool:
    return operation in ALLOWED_OPERATIONS
