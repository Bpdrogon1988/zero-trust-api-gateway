import base64
import json
import os
from typing import Optional

import boto3


_secrets_client = None
_kms_client = None


def _get_region_name() -> Optional[str]:
    return os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")


def _get_secrets_client():
    global _secrets_client
    if _secrets_client is None:
        _secrets_client = boto3.client("secretsmanager", region_name=_get_region_name())
    return _secrets_client


def _get_kms_client():
    global _kms_client
    if _kms_client is None:
        _kms_client = boto3.client("kms", region_name=_get_region_name())
    return _kms_client


def get_secret_from_secrets_manager(secret_name: str, field: Optional[str] = None) -> str:
    client = _get_secrets_client()
    response = client.get_secret_value(SecretId=secret_name)
    if "SecretString" in response and response["SecretString"] is not None:
        secret_string = response["SecretString"]
        if field:
            try:
                data = json.loads(secret_string)
                if field in data:
                    return str(data[field])
            except json.JSONDecodeError:
                pass
        return secret_string
    if "SecretBinary" in response and response["SecretBinary"] is not None:
        binary = response["SecretBinary"]
        if isinstance(binary, (bytes, bytearray)):
            return binary.decode("utf-8")
        return str(binary)
    raise RuntimeError(f"Secret {secret_name} has no retrievable value")


def decrypt_kms_ciphertext(b64_ciphertext: str) -> str:
    ciphertext = base64.b64decode(b64_ciphertext)
    client = _get_kms_client()
    result = client.decrypt(CiphertextBlob=ciphertext)
    plaintext_bytes = result.get("Plaintext")
    if not plaintext_bytes:
        raise RuntimeError("KMS did not return plaintext")
    if isinstance(plaintext_bytes, (bytes, bytearray)):
        return plaintext_bytes.decode("utf-8")
    return str(plaintext_bytes)


def resolve_secret(
    direct_env_var_name: str,
    secret_name_env_var_name: str,
    kms_cipher_env_var_name: str,
    required: bool = True,
) -> str:
    direct_value = os.getenv(direct_env_var_name)
    if direct_value:
        return direct_value

    secret_name = os.getenv(secret_name_env_var_name)
    if secret_name:
        field_env_name = f"{secret_name_env_var_name}_FIELD"
        field = os.getenv(field_env_name)
        return get_secret_from_secrets_manager(secret_name, field=field)

    kms_b64 = os.getenv(kms_cipher_env_var_name)
    if kms_b64:
        return decrypt_kms_ciphertext(kms_b64)

    if required:
        raise RuntimeError(
            f"Missing secret: set {direct_env_var_name} or {secret_name_env_var_name} or {kms_cipher_env_var_name}"
        )
    return ""

