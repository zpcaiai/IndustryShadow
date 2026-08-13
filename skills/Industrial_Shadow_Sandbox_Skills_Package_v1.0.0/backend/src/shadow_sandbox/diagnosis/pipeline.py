from shadow_sandbox.application import ApplicationService


class DiagnosisPipeline:
    def __init__(self, application: ApplicationService) -> None:
        self.application = application

    def quality(self, actor, run_id, request):
        return self.application.quality_and_detect(actor, run_id, request)

    def residuals(self, actor, run_id, request):
        return self.application.residuals_and_consistency(actor, run_id, request)

    def evidence(self, actor, run_id, request):
        return self.application.materialize_evidence(actor, run_id, request)

    def hypotheses(self, actor, run_id, request):
        return self.application.generate_hypotheses(actor, run_id, request)
