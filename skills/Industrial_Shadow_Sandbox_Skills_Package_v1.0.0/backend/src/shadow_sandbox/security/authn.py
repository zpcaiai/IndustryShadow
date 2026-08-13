from . import LocalTokenCodec


def authenticate(codec: LocalTokenCodec, bearer_token: str):
    return codec.decode(bearer_token.removeprefix("Bearer ").strip())
