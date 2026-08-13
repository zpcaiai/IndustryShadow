def get_asset_metadata(application, actor, model_id: str):
    return application.resources.get(actor, "asset_model_draft", model_id).as_dict()
