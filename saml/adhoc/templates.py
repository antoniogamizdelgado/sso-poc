from dataclasses import dataclass
from datetime import datetime, timezone
import uuid
from pathlib import Path


def _load_template(template_name: str) -> str:
    """Load a template file from the templates directory"""
    template_dir = Path(__file__).parent / "templates"
    template_path = template_dir / template_name
    with open(template_path, "r") as f:
        return f.read()


@dataclass
class AuthnRequestTemplate:
    request_id: str
    issue_instant: str
    assertion_consumer_service_url: str
    destination: str
    issuer: str

    @classmethod
    def create(
        cls,
        assertion_consumer_service_url: str,
        destination: str,
        issuer: str,
    ) -> "AuthnRequestTemplate":
        return cls(
            request_id=f"_{uuid.uuid4()}",
            issue_instant=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            assertion_consumer_service_url=assertion_consumer_service_url,
            destination=destination,
            issuer=issuer,
        )

    def render(self) -> str:
        """Render the AuthnRequest XML template"""
        template = _load_template("authn_request.xml")
        return template.format(
            request_id=self.request_id,
            issue_instant=self.issue_instant,
            assertion_consumer_service_url=self.assertion_consumer_service_url,
            destination=self.destination,
            issuer=self.issuer,
        )


@dataclass
class SPMetadataTemplate:
    entity_id: str
    assertion_consumer_service_url: str

    @classmethod
    def create(
        cls,
        entity_id: str,
        assertion_consumer_service_url: str,
    ) -> "SPMetadataTemplate":
        return cls(
            entity_id=entity_id,
            assertion_consumer_service_url=assertion_consumer_service_url,
        )

    def render(self) -> str:
        """Render the SP metadata XML template"""
        template = _load_template("sp_metadata.xml")
        return template.format(
            entity_id=self.entity_id,
            assertion_consumer_service_url=self.assertion_consumer_service_url,
        )
