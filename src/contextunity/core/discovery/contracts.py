"""Abstract storage contracts for the project discovery subsystem.
Defines ``ProjectStore`` and ``ServiceStore`` ABCs that concrete backends
(in-memory dict, Redis) must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from contextunity.core.types import JsonDict

from .types import ProjectKeyInfo


class ProjectStore(ABC):
    """Storage boundary for project ownership and key material."""

    @abstractmethod
    def register(
        self,
        project_id: str,
        *,
        owner_project: str | None = None,
        tools: list[str] | None = None,
        project_secret: str | None = None,
        public_key_b64: str | None = None,
        public_key_kid: str | None = None,
        api_keys: dict[str, str] | None = None,
    ) -> bool:
        """Register or update a project record in the store.

        Args:
            project_id: The unique identifier of the project.
            owner_project: Project owner id (defaults to ``project_id``).
            tools: Optional list of enabled tool names for this project.
            project_secret: Optional project HMAC secret.
            public_key_b64: Optional Ed25519 public key base64 string.
            public_key_kid: Optional Key ID (KID) of the public key.
            api_keys: Optional mapping of service API keys.

        Returns:
            bool: True if the project was successfully registered or updated, False otherwise.
        """

    @abstractmethod
    def verify_owner(self, project_id: str, claimed_owner: str) -> bool:
        """Verify whether ``claimed_owner`` owns the specified project.

        Args:
            project_id: The unique identifier of the project.
            claimed_owner: The project id claiming ownership.

        Returns:
            bool: True if the owner matches or the project is unregistered.
        """

    @abstractmethod
    def list_projects(self) -> list[JsonDict]:
        """Retrieve a list of all registered projects for admin/introspection.

        Returns:
            list[JsonDict]: A list of project record dictionaries.
        """

    @abstractmethod
    def update_public_key(self, project_id: str, public_key_b64: str, public_key_kid: str) -> bool:
        """Update the cached public key material for a project.

        Args:
            project_id: The unique identifier of the project.
            public_key_b64: The base64-encoded Ed25519 public key.
            public_key_kid: The key identifier (KID) for the new public key.

        Returns:
            bool: True if the update was successful, False otherwise.
        """

    @abstractmethod
    def update_stream_secret(self, project_id: str, stream_secret: str) -> bool:
        """Update the cached stream secret material for a project.

        Args:
            project_id: The unique identifier of the project.
            stream_secret: The new stream secret.

        Returns:
            bool: True if the update was successful, False otherwise.
        """

    @abstractmethod
    def get_stream_secret(self, project_id: str) -> str | None:
        """Retrieve the cached stream secret for a project if present and valid.

        Args:
            project_id: The unique identifier of the project.

        Returns:
            str | None: The stream secret if it exists and is valid, otherwise None.
        """

    @abstractmethod
    def get_key_material(self, project_id: str) -> ProjectKeyInfo | None:
        """Retrieve the decrypted key material for a project.

        Args:
            project_id: The unique identifier of the project.

        Returns:
            ProjectKeyInfo | None: The key information if found, otherwise None.
        """
