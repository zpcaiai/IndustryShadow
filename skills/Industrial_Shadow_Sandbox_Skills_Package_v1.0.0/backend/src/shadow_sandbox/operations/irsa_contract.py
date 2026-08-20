from __future__ import annotations

IRSA_ROLE_ANNOTATION = "eks.amazonaws.com/role-arn"
IRSA_VOLUME_NAME = "aws-iam-token"
IRSA_MOUNT_PATH = "/var/run/secrets/eks.amazonaws.com/serviceaccount"
IRSA_TOKEN_PATH = f"{IRSA_MOUNT_PATH}/token"
IRSA_TOKEN_AUDIENCE = "sts.amazonaws.com"
IRSA_TOKEN_EXPIRATION_SECONDS = 3600
IRSA_TOKEN_DEFAULT_MODE = 0o400

# This is the exact shape used by the EKS IAM webhook.  Supplying the same
# volume name and mount path lets admission recognise the existing projection
# instead of creating a second credential source.
IRSA_TOKEN_PROJECTION = {
    "name": IRSA_VOLUME_NAME,
    "projected": {
        "defaultMode": IRSA_TOKEN_DEFAULT_MODE,
        "sources": [
            {
                "serviceAccountToken": {
                    "audience": IRSA_TOKEN_AUDIENCE,
                    "expirationSeconds": IRSA_TOKEN_EXPIRATION_SECONDS,
                    "path": "token",
                }
            }
        ],
    },
}
IRSA_TOKEN_MOUNT = {
    "name": IRSA_VOLUME_NAME,
    "mountPath": IRSA_MOUNT_PATH,
    "readOnly": True,
}
