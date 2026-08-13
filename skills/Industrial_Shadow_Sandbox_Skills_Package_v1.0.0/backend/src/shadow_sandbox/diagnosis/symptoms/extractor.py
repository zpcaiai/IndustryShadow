def extract(service, **observation):
    _, symptom = service.materialize(**observation)
    return symptom
