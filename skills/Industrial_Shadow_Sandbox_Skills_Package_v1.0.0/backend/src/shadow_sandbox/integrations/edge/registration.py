from shadow_sandbox.application import ApplicationService


class EdgeRegistrationService:
    def __init__(self, application: ApplicationService) -> None:
        self.application = application

    def register(self, actor, request):
        return self.application.register_edge_gateway(actor, request)
