"""
HashiCorp Vault integration for secrets management.
Provides dynamic secrets, API key rotation, and credential management.
"""

import os
import hvac
import asyncio
from typing import Optional, Dict, Any
from functools import lru_cache
from contextlib import asynccontextmanager
from .config import get_settings
from .logging import get_logger

logger = get_logger(__name__)


class VaultClient:
    """Wrapper around HashiCorp Vault client."""

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        role_id: Optional[str] = None,
        secret_id: Optional[str] = None,
        mount_point: str = "secret",
    ):
        self.url = url or "http://localhost:8200"
        self.token = token
        self.role_id = role_id
        self.secret_id = secret_id
        self.mount_point = mount_point
        self._client: Optional[hvac.Client] = None
        self._lease_id: Optional[str] = None

    def _get_client(self) -> hvac.Client:
        """Get or create Vault client."""
        if self._client is None:
            self._client = hvac.Client(url=self.url)

            # Authenticate with AppRole if credentials provided
            if self.role_id and self.secret_id:
                self._client.auth.approle.login(
                    role_id=self.role_id,
                    secret_id=self.secret_id,
                )
                logger.info("vault_approle_authenticated", url=self.url)
            elif self.token:
                self._client.token = self.token
                logger.info("vault_token_authenticated", url=self.url)
            else:
                # Try environment variable
                token = os.environ.get("VAULT_TOKEN")
                if token:
                    self._client.token = token
                    logger.info("vault_env_token_authenticated", url=self.url)
                else:
                    logger.warning("vault_no_auth_method", url=self.url)

        return self._client

    def read_secret(self, path: str, version: int = 1) -> Dict[str, Any]:
        """Read a secret from Vault."""
        client = self._get_client()
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path,
                version=version,
                mount_point=self.mount_point,
            )
            return response.get("data", {}).get("data", {})
        except Exception as e:
            logger.error("vault_read_failed", path=path, error=str(e))
            raise

    def write_secret(self, path: str, data: Dict[str, Any]) -> bool:
        """Write a secret to Vault."""
        client = self._get_client()
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                mount_point=self.mount_point,
            )
            logger.info("vault_secret_written", path=path)
            return True
        except Exception as e:
            logger.error("vault_write_failed", path=path, error=str(e))
            return False

    def delete_secret(self, path: str) -> bool:
        """Delete a secret from Vault."""
        client = self._get_client()
        try:
            client.secrets.kv.v2.delete_secret_versions(
                path=path,
                versions=[1, 2],
                mount_point=self.mount_point,
            )
            logger.info("vault_secret_deleted", path=path)
            return True
        except Exception as e:
            logger.error("vault_delete_failed", path=path, error=str(e))
            return False

    def list_secrets(self, path: str = "") -> list:
        """List secrets at a path."""
        client = self._get_client()
        try:
            response = client.secrets.kv.v2.list_secrets(
                path=path,
                mount_point=self.mount_point,
            )
            return response.get("data", {}).get("keys", [])
        except Exception as e:
            logger.error("vault_list_failed", path=path, error=str(e))
            return []

    def generate_database_credentials(self, role: str) -> Dict[str, str]:
        """Generate dynamic database credentials."""
        client = self._get_client()
        try:
            response = client.secrets.database.generate_credentials(
                name=role,
                mount_point="database",
            )
            self._lease_id = response.get("lease_id")
            return {
                "username": response["data"]["username"],
                "password": response["data"]["password"],
                "lease_id": self._lease_id,
                "lease_duration": response["lease_duration"],
            }
        except Exception as e:
            logger.error("vault_database_creds_failed", role=role, error=str(e))
            raise

    def renew_lease(self, lease_id: Optional[str] = None, increment: int = 3600) -> bool:
        """Renew a lease."""
        client = self._get_client()
        try:
            client.sys.renew_lease(
                lease_id=lease_id or self._lease_id,
                increment=increment,
            )
            logger.info("vault_lease_renewed", lease_id=lease_id or self._lease_id)
            return True
        except Exception as e:
            logger.error("vault_lease_renew_failed", error=str(e))
            return False

    def generate_api_key(self, service: str, scopes: list) -> Dict[str, Any]:
        """Generate an API key for a service."""
        api_key = os.urandom(32).hex()
        secret_path = f"api-keys/{service}"
        data = {
            "key": api_key,
            "scopes": scopes,
            "created_at": os.times()[4],
        }
        if self.write_secret(secret_path, data):
            return data
        raise Exception("Failed to generate API key")

    def get_api_key(self, service: str) -> Optional[str]:
        """Get an API key for a service."""
        data = self.read_secret(f"api-keys/{service}")
        return data.get("key")

    def rotate_api_key(self, service: str, scopes: list) -> str:
        """Rotate an API key for a service."""
        self.delete_secret(f"api-keys/{service}")
        return self.generate_api_key(service, scopes)["key"]

    def close(self):
        """Close the Vault client."""
        self._client = None
        self._lease_id = None


# Global Vault client instance
_vault_client: Optional[VaultClient] = None


def get_vault_client() -> VaultClient:
    """Get or create Vault client."""
    global _vault_client
    if _vault_client is None:
        settings = get_settings()
        _vault_client = VaultClient(
            url=settings.vault_url,
            token=settings.vault_token,
            role_id=settings.vault_role_id,
            secret_id=settings.vault_secret_id,
            mount_point=settings.vault_mount_point,
        )
    return _vault_client


@asynccontextmanager
async def vault_secret(path: str, version: int = 1):
    """Context manager for reading a Vault secret."""
    client = get_vault_client()
    try:
        data = client.read_secret(path, version)
        yield data
    except Exception:
        raise
    finally:
        client.close()