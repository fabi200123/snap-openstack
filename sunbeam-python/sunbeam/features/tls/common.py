# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import logging

import click
import pydantic
from packaging.version import Version
from rich.console import Console
from rich.status import Status

from sunbeam.clusterd.service import ConfigItemNotFoundException
from sunbeam.core import questions
from sunbeam.core.common import (
    BaseStep,
    Result,
    ResultType,
    read_config,
    run_plan,
    update_config,
)
from sunbeam.core.deployment import Deployment
from sunbeam.core.juju import (
    ActionFailedException,
    JujuHelper,
    LeaderNotFoundException,
    run_sync,
)
from sunbeam.core.manifest import FeatureConfig
from sunbeam.core.openstack import OPENSTACK_MODEL
from sunbeam.features.interface.v1.base import BaseFeatureGroup
from sunbeam.features.interface.v1.openstack import (
    OpenStackControlPlaneFeature,
    WaitForApplicationsStep,
)
from sunbeam.utils import pass_method_obj

LOG = logging.getLogger(__name__)
console = Console()

# Shared Juju config key for TLS provider
CERTIFICATE_FEATURE_KEY = "TlsProvider"
# Timeout for ingress relations to settle
INGRESS_CHANGE_APPLICATION_TIMEOUT = 1200


class TlsFeatureGroup(BaseFeatureGroup):
    name = "tls"

    @click.group(name="ca")
    @pass_method_obj
    def ca(self, deployment: Deployment) -> None:
        """Use the built-in OpenSSL CA provider."""

    @click.group(name="vault")
    @pass_method_obj
    def vault(self, deployment: Deployment) -> None:
        """Use HashiCorp Vault as an intermediary CA."""


class _AddCACertsStep(BaseStep):
    """Transfer CA certificates to Keystone."""

    def __init__(
        self,
        jhelper: JujuHelper,
        name: str,
        ca_cert: str,
        ca_chain: str,
    ):
        super().__init__(
            "Transfer CA certs to keystone",
            "Transferring CA certificates to keystone",
        )
        self.jhelper = jhelper
        self.cert_name = name.lower()
        self.ca_cert = ca_cert
        self.ca_chain = ca_chain
        self.app = "keystone"
        self.model = OPENSTACK_MODEL

    def is_skip(self, status: Status | None = None) -> Result:
        unit = run_sync(self.jhelper.get_leader_unit(self.app, self.model))
        result = run_sync(
            self.jhelper.run_action(unit, self.model, "list-ca-certs")
        )
        result.pop("return-code", None)
        if self.cert_name in result:
            return Result(ResultType.SKIPPED)
        return Result(ResultType.COMPLETED)

    def run(self, status: Status | None = None) -> Result:
        unit = run_sync(self.jhelper.get_leader_unit(self.app, self.model))
        params = {"name": self.cert_name, "ca": self.ca_cert, "chain": self.ca_chain}
        run_sync(
            self.jhelper.run_action(unit, self.model, "add-ca-certs", params)
        )
        return Result(ResultType.COMPLETED)


class _RemoveCACertsStep(BaseStep):
    """Remove CA certificates from Keystone."""

    def __init__(
        self,
        jhelper: JujuHelper,
        name: str,
        feature_key: str,
    ):
        super().__init__(
            "Remove CA certs from keystone",
            "Removing CA certificates from keystone",
        )
        self.jhelper = jhelper
        self.cert_name = name.lower()
        self.feature_key = feature_key.lower()
        self.app = "keystone"
        self.model = OPENSTACK_MODEL

    def is_skip(self, status: Status | None = None) -> Result:
        unit = run_sync(self.jhelper.get_leader_unit(self.app, self.model))
        result = run_sync(
            self.jhelper.run_action(unit, self.model, "list-ca-certs")
        )
        result.pop("return-code", None)
        name = self.cert_name.replace(".", "-")
        if name not in result:
            return Result(ResultType.SKIPPED)
        return Result(ResultType.COMPLETED)

    def run(self, status: Status | None = None) -> Result:
        unit = run_sync(self.jhelper.get_leader_unit(self.app, self.model))
        # Try cert_name then feature_key for backwards compatibility
        for nm in (self.cert_name, self.feature_key):
            try:
                run_sync(
                    self.jhelper.run_action(unit, self.model, "remove-ca-certs", {"name": nm})
                )
                break
            except ActionFailedException:
                continue
        return Result(ResultType.COMPLETED)


def certificate_questions(unit: str, subject: str):
    return {
        "certificate": questions.PromptQuestion(
            f"Base64 encoded Certificate for {unit} CSR Unique ID: {subject}",
        ),
    }


def get_outstanding_certificate_requests(app: str, model: str, jhelper: JujuHelper) -> dict:
    """Get outstanding certificate requests from manual-tls-certificate operator."""
    unit = run_sync(jhelper.get_leader_unit(app, model))
    return run_sync(jhelper.run_action(unit, model, "get-outstanding-certificate-requests"))


class TlsCAFeatureConfig(FeatureConfig):
    ca: str | None = None
    ca_chain: str | None = None
    endpoints: list[str] = pydantic.Field(default_factory=list)


class TlsCAFeature(OpenStackControlPlaneFeature):
    """TLS feature backed by OpenSSL CA."""
    version = Version("0.0.1")
    feature_key = "tls.ca"
    group = TlsFeatureGroup

    @property
    def ca_cert_name(self) -> str:
        return self.feature_key.replace(".", "-")

    def provider_config(self, deployment: Deployment) -> dict:
        try:
            return read_config(deployment.get_client(), CERTIFICATE_FEATURE_KEY)
        except ConfigItemNotFoundException:
            return {}

    def pre_enable(
        self,
        deployment: Deployment,
        config: TlsCAFeatureConfig,
        show_hints: bool,
    ) -> None:
        super().pre_enable(deployment, config, show_hints)
        provider = self.provider_config(deployment).get("provider")
        if provider and provider != self.feature_key:
            raise Exception(f"Already using {provider!r} as TLS provider")

    def post_enable(
        self,
        deployment: Deployment,
        config: TlsCAFeatureConfig,
        show_hints: bool,
    ) -> None:
        j = JujuHelper(deployment.get_connected_controller())
        run_plan(
            [
                _AddCACertsStep(
                    j,
                    self.ca_cert_name,
                    config.ca,  # type: ignore
                    config.ca_chain,  # type: ignore
                )
            ],
            console,
            show_hints,
        )
        update_config(
            deployment.get_client(),
            CERTIFICATE_FEATURE_KEY,
            {
                "provider": self.feature_key,
                "ca": config.ca,
                "chain": config.ca_chain,
                "endpoints": config.endpoints,
            },
        )

    def post_disable(self, deployment: Deployment, show_hints: bool) -> None:
        super().post_disable(deployment, show_hints)
        client = deployment.get_client()
        j = JujuHelper(deployment.get_connected_controller())
        apps = ["traefik", "traefik-public", "keystone"]
        if client.cluster.list_nodes_by_role("storage"):
            apps.append("traefik-rgw")
        run_plan(
            [
                _RemoveCACertsStep(
                    j,
                    self.ca_cert_name,
                    self.feature_key,
                ),
                WaitForApplicationsStep(
                    j,
                    apps,
                    OPENSTACK_MODEL,
                    INGRESS_CHANGE_APPLICATION_TIMEOUT,
                ),
            ],
            console,
            show_hints,
        )
        update_config(deployment.get_client(), CERTIFICATE_FEATURE_KEY, {})


class TlsFeatureConfig(FeatureConfig):
    ca: str | None = None
    ca_chain: str | None = None
    endpoints: list[str] = pydantic.Field(default_factory=list)


class TlsFeature(OpenStackControlPlaneFeature):
    """TLS feature backed by HashiCorp Vault intermediary CA."""
    version = Version("0.0.1")
    feature_key = "tls.vault"
    group = TlsFeatureGroup

    @property
    def ca_cert_name(self) -> str:
        return self.feature_key.replace(".", "-")

    def provider_config(self, deployment: Deployment) -> dict:
        try:
            return read_config(deployment.get_client(), CERTIFICATE_FEATURE_KEY)
        except ConfigItemNotFoundException:
            return {}

    def pre_enable(
        self,
        deployment: Deployment,
        config: TlsFeatureConfig,
        show_hints: bool,
    ) -> None:
        super().pre_enable(deployment, config, show_hints)
        provider = self.provider_config(deployment).get("provider")
        if provider and provider != self.feature_key:
            raise Exception(f"Already using {provider!r} as TLS provider")

    def post_enable(
        self,
        deployment: Deployment,
        config: TlsFeatureConfig,
        show_hints: bool,
    ) -> None:
        j = JujuHelper(deployment.get_connected_controller())
        # Insert your Vault-specific CSR/intermediate issuance here
        run_plan(
            [
                _AddCACertsStep(
                    j,
                    self.ca_cert_name,
                    config.ca,  # type: ignore
                    config.ca_chain,  # type: ignore
                )
            ],
            console,
            show_hints,
        )
        update_config(
            deployment.get_client(),
            CERTIFICATE_FEATURE_KEY,
            {
                "provider": self.feature_key,
                "ca": config.ca,
                "chain": config.ca_chain,
                "endpoints": config.endpoints,
            },
        )

    def post_disable(self, deployment: Deployment, show_hints: bool) -> None:
        super().post_disable(deployment, show_hints)
        client = deployment.get_client()
        j = JujuHelper(deployment.get_connected_controller())
        apps = ["traefik", "traefik-public", "keystone"]
        if client.cluster.list_nodes_by_role("storage"):
            apps.append("traefik-rgw")
        run_plan(
            [
                _RemoveCACertsStep(
                    j,
                    self.ca_cert_name,
                    self.feature_key,
                ),
                WaitForApplicationsStep(
                    j,
                    apps,
                    OPENSTACK_MODEL,
                    INGRESS_CHANGE_APPLICATION_TIMEOUT,
                ),
            ],
            console,
            show_hints,
        )
        update_config(deployment.get_client(), CERTIFICATE_FEATURE_KEY, {})
