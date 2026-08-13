from shadow_sandbox.application import ApplicationService


def registry(application: ApplicationService):
    return application.version()
