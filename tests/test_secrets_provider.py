import pytest

from app.secrets_provider import (
    AwsSecretsManagerProvider,
    EnvSecretProvider,
    SecretResolutionError,
    VaultProvider,
    build_secret_provider,
)


def test_env_provider_reads_environment(monkeypatch):
    monkeypatch.setenv("SOME_SECRET", "value-123")
    provider = EnvSecretProvider()
    assert provider.get_secret("SOME_SECRET") == "value-123"
    assert provider.get_secret("MISSING", "fallback") == "fallback"
    assert provider.get_secret("MISSING") is None


def test_build_defaults_to_env(monkeypatch):
    monkeypatch.delenv("SECRETS_BACKEND", raising=False)
    assert isinstance(build_secret_provider(), EnvSecretProvider)


def test_build_rejects_unknown_backend(monkeypatch):
    monkeypatch.setenv("SECRETS_BACKEND", "gcp")
    with pytest.raises(SecretResolutionError):
        build_secret_provider()


class _FakeAwsClient:
    def __init__(self, store):
        self._store = store

    def get_secret_value(self, SecretId):  # noqa: N803 - match boto3 signature
        if SecretId not in self._store:
            raise type("ResourceNotFoundException", (Exception,), {})()
        return {"SecretString": self._store[SecretId]}


def test_aws_provider_resolves_prefixed_secret_and_caches():
    client = _FakeAwsClient({"prod/SECRET_KEY": "aws-secret"})
    provider = AwsSecretsManagerProvider(prefix="prod/", client=client)
    assert provider.get_secret("SECRET_KEY") == "aws-secret"
    # cached — a second call must not require the store to still have it
    provider._client = _FakeAwsClient({})
    assert provider.get_secret("SECRET_KEY") == "aws-secret"


def test_aws_provider_missing_returns_default():
    provider = AwsSecretsManagerProvider(client=_FakeAwsClient({}))
    assert provider.get_secret("NOPE", "default-val") == "default-val"


def test_aws_provider_backend_error_raises():
    class _BoomClient:
        def get_secret_value(self, SecretId):  # noqa: N803
            raise RuntimeError("credentials missing")

    provider = AwsSecretsManagerProvider(client=_BoomClient())
    with pytest.raises(SecretResolutionError):
        provider.get_secret("SECRET_KEY")


class _FakeVaultKV:
    def __init__(self, store):
        self._store = store

    def read_secret_version(self, path, mount_point):
        if path not in self._store:
            raise type("InvalidPath", (Exception,), {})()
        return {"data": {"data": {"value": self._store[path]}}}


class _FakeVaultClient:
    def __init__(self, store):
        self.secrets = type("S", (), {})()
        self.secrets.kv = type("KV", (), {})()
        self.secrets.kv.v2 = _FakeVaultKV(store)


def test_vault_provider_reads_value_field():
    client = _FakeVaultClient({"guard-bands/SECRET_KEY": "vault-secret"})
    provider = VaultProvider(client=client)
    assert provider.get_secret("SECRET_KEY") == "vault-secret"


def test_vault_provider_missing_returns_default():
    provider = VaultProvider(client=_FakeVaultClient({}))
    assert provider.get_secret("NOPE", "d") == "d"
