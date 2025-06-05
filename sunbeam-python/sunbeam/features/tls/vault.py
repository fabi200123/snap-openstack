# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import logging
from pathlib import Path

import click
import yaml
from packaging.version import Version
from rich.console import Console
from rich.status import Status

from sunbeam.clusterd.client import Client
from sunbeam.core import questions
from sunbeam.core.common import (
    FORMAT_TABLE,
    FORMAT_YAML,
    BaseStep,
    Result,
    ResultType,
    read_config,
    run_plan,
    str_presenter,
)
from sunbeam.core.deployment import Deployment
from sunbeam.core.juju import (
    ActionFailedException,
    JujuHelper,
    LeaderNotFoundException,
    run_sync,
)
from sunbeam.core.manifest import (
    AddManifestStep,
    CharmManifest,
    FeatureConfig,
    SoftwareConfig,
)
from sunbeam.core.openstack import OPENSTACK_MODEL
from sunbeam.features.interface.utils import validate_ca_certificate, validate_ca_chain
from sunbeam.features.interface.v1.openstack import (
    TerraformPlanLocation,
    WaitForApplicationsStep,
)
from sunbeam.features.tls.common import (
    INGRESS_CHANGE_APPLICATION_TIMEOUT,
    TlsFeature,
    TlsFeatureConfig,
    certificate_questions,
    get_outstanding_certificate_requests,
)
from sunbeam.utils import click_option_show_hints, pass_method_obj

LOG = logging.getLogger(__name__)
console = Console()

VAULT_APP = "vault"
MANUAL_CA_CONFIG = "FeatureCACertificatesConfig"


class VaultTlsFeatureConfig(TlsFeatureConfig):
    ca: str
    ca_chain: str
    endpoints: list[str] = ["public"]


class ConfigureVaultIntermediateCAStep(BaseStep):
    _CONFIG = "FeatureVaultIntermediateConfig"

    def __init__(
        self,
        client: Client,
        jhelper: JujuHelper,
        config: VaultTlsFeatureConfig,
        deployment_preseed: dict | None = None,
    ):
        super().__init__(
            "Configure Vault Intermediate CA",
            "Configuring Vault as an intermediate Certificate Authority",
        )
        self.client = client
        self.jhelper = jhelper
        self.config = config
        self.preseed = deployment_preseed or {}
        self.cert = ""
        self.chain = ""

    def has_prompts(self) -> bool:
        return True

    def prompt(
        self, console: Console | None = None, show_hint: bool = False
    ) -> None:
        try:
            leader = run_sync(
                self.jhelper.get_leader_unit(VAULT_APP, OPENSTACK_MODEL)
            )
        except LeaderNotFoundException as e:
            raise click.ClickException(f"Unable to get Vault leader: {e}")

        action = run_sync(
            self.jhelper.run_action(leader, OPENSTACK_MODEL, "get-csr")
        )
        if action.get("return-code", 1) != 0:
            raise click.ClickException("Failed to fetch intermediate CSR from Vault")

        csr_pem = action.get("output") or action.get("results", {}).get("output")
        if not csr_pem:
            raise click.ClickException("No CSR returned from Vault")

        console.print("[bold]Vault Intermediate CA CSR:[/]")
        console.print(csr_pem)

        variables = questions.load_answers(self.client, self._CONFIG)
        variables.setdefault("certificate", "")
        variables.setdefault("root_ca", "")

        bank = questions.QuestionBank(
            questions=certificate_questions("unit", "subject"),
            console=console,
            preseed=self.preseed,
            previous_answers=variables,
            show_hint=show_hint,
        )
        cert = bank.certificate.ask()
        root = bank.root_ca.ask()

        if not cert or not root:
            raise click.ClickException("Invalid intermediate certificate or root CA chain")

        self.cert = cert
        self.chain = root

        variables["certificate"] = cert
        variables["root_ca"] = root
        questions.write_answers(self.client, self._CONFIG, variables)

    def is_skip(self, status: Status | None = None) -> Result:
        return Result(ResultType.COMPLETED)

    def run(self, status: Status | None = None) -> Result:
        try:
            leader = run_sync(
                self.jhelper.get_leader_unit(VAULT_APP, OPENSTACK_MODEL)
            )
        except LeaderNotFoundException as e:
            LOG.debug("Unable to get Vault leader")
            return Result(ResultType.FAILED, str(e))

        params = {"pem": self.cert, "root-ca": self.chain}
        try:
            action = run_sync(
                self.jhelper.run_action(
                    leader, OPENSTACK_MODEL, "upload-signed-csr", params
                )
            )
        except ActionFailedException as e:
            LOG.debug("upload-signed-csr action failed")
            return Result(ResultType.FAILED, str(e))

        if action.get("return-code", 1) != 0:
            return Result(ResultType.FAILED, "upload-signed-csr failed")

        try:
            reissue = run_sync(
                self.jhelper.run_action(
                    leader, OPENSTACK_MODEL, "reissue-certificates"
                )
            )
        except ActionFailedException as e:
            LOG.debug("reissue-certificates action failed")
            return Result(ResultType.FAILED, str(e))

        if reissue.get("return-code", 1) != 0:
            return Result(ResultType.FAILED, "reissue-certificates failed")

        return Result(ResultType.COMPLETED)


class VaultTlsFeature(TlsFeature):
    version = Version("0.2.0")
    name = "tls.vault"
    tf_plan_location = TerraformPlanLocation.SUNBEAM_TERRAFORM_REPO

    def config_type(self) -> type | None:
        """Return the config type for the feature."""
        return VaultTlsFeatureConfig

    def default_software_overrides(self) -> SoftwareConfig:
        """Feature software configuration."""
        return SoftwareConfig(
            charms={"manual-tls-certificates": CharmManifest(
                channel="latest/stable")}
        )

    def manifest_attributes_tfvar_map(self) -> dict:
        """Manifest attributes terraformvars map."""
        return {
            self.tfplan: {
                "charms": {
                    "manual-tls-certificates": {
                        "channel": "manual-tls-certificates-channel",
                        "revision": "manual-tls-certificates-revision",
                        "config": "manual-tls-certificates-config",
                    }
                }
            }
        }

    def preseed_questions_content(self) -> list:
        """Generate preseed manifest content."""
        certificate_question_bank = questions.QuestionBank(
            questions=certificate_questions("unit", "subject"),
            console=console,
            previous_answers={},
        )
        content = questions.show_questions(
            certificate_question_bank,
            section="certificates",
            subsection="<CSR x500UniqueIdentifier>",
            section_description="TLS Certificates",
            comment_out=True,
        )
        return content

    def set_application_names(self, deployment: Deployment) -> list:
        """Application names handled by the terraform plan."""
        return ["vault"]

    def set_tfvars_on_enable(
        self, deployment: Deployment, config: VaultTlsFeatureConfig
    ) -> dict:
        """Set terraform variables to enable the application."""
        tfvars: dict[str, str | bool] = {
            "traefik-to-tls-provider": VAULT_APP,}
        if "public" in config.endpoints:
            tfvars.update({"enable-tls-for-public-endpoint": True})
        if "internal" in config.endpoints:
            tfvars.update({"enable-tls-for-internal-endpoint": True})
        if "rgw" in config.endpoints:
            tfvars.update({"enable-tls-for-rgw-endpoint": True})

        return tfvars

    def set_tfvars_on_disable(self, deployment: Deployment) -> dict:
        """Set terraform variables to disable the application."""
        tfvars: dict[str, None | str | bool] = {"traefik-to-tls-provider": None}
        provider_config = self.provider_config(deployment)
        endpoints = provider_config.get("endpoints", [])
        if "public" in endpoints:
            tfvars.update({"enable-tls-for-public-endpoint": False})
        if "internal" in endpoints:
            tfvars.update({"enable-tls-for-internal-endpoint": False})
        if "rgw" in endpoints:
            tfvars.update({"enable-tls-for-rgw-endpoint": False})

        return tfvars

    def set_tfvars_on_resize(
        self, deployment: Deployment, config: FeatureConfig
    ) -> dict:
        """Set terraform variables to resize the application."""
        return {}

    def preseed_questions_content(self) -> list:
        bank = questions.QuestionBank(
            questions=certificate_questions("unit", "subject"),
            console=console,
            previous_answers={},
        )
        return questions.show_questions(
            bank,
            section="vault",
            subsection="intermediate-ca",
            section_description="Vault Intermediate CA Configuration",
            comment_out=True,
        )

    @click.group()
    def tls_group(self) -> None:
        """Manage TLS features."""

    @click.group()
    def ca_group(self) -> None:
        """Manage Vault as CA."""

    @ca_group.command(name="enable")
    @click.option(
        "--endpoint",
        "endpoints",
        multiple=True,
        default=["public"],
        type=click.Choice(["public", "internal", "rgw"], case_sensitive=False),
        help="Specify endpoints to secure with TLS.",
    )
    @click.option(
        "--ca",
        required=True,
        type=str,
        callback=validate_ca_certificate,
        help="Base64 encoded Intermediate CA certificate",
    )
    @click.option(
        "--ca-chain",
        required=True,
        type=str,
        callback=validate_ca_chain,
        help="Base64 encoded Root CA certificate(s) chain",
    )
    @click_option_show_hints
    @pass_method_obj
    def enable_cmd(
        self,
        deployment: Deployment,
        ca: str,
        ca_chain: str,
        endpoints: list[str],
        show_hints: bool,
    ):
        """Enable Vault as an intermediate CA."""
        feature_manager = deployment.get_feature_manager()
        enabled_features = feature_manager.enabled_features(deployment)
        for feature in enabled_features:
            if VAULT_APP != feature.name:
                raise click.ClickException(
                    "Vault must be enabled first (run `sunbeam enable vault`)."
                )

        jhelper = JujuHelper(deployment.get_connected_controller())
        try:
            leader = run_sync(jhelper.get_leader_unit(VAULT_APP, OPENSTACK_MODEL))
            status = run_sync(
                jhelper.run_action(leader, OPENSTACK_MODEL, "status")
            )
        except Exception as e:
            raise click.ClickException(f"Unable to query Vault status: {e}")
        sealed = status.get("results", {}).get("sealed")
        if sealed in (True, "true", "True"):
            raise click.ClickException(
                "Vault is sealed; unseal before configuring intermediate CA."
            )

        try:
            manual = read_config(deployment, MANUAL_CA_CONFIG)
            if manual.get("ca") or manual.get("chain"):
                raise click.ClickException(
                    "Manual TLS CA feature already configured; disable it first."
                )
        except Exception:
            pass

        cfg = VaultTlsFeatureConfig(
            ca=ca, ca_chain=ca_chain, endpoints=endpoints
        )
        # self.enable_feature(deployment, cfg, show_hints)

    @ca_group.command(name="disable")
    @click_option_show_hints
    @pass_method_obj
    def disable_cmd(self, deployment: Deployment, show_hints: bool):
        """Disable Vault-based TLS feature."""
        self.disable_feature(deployment, show_hints)
        console.print("Vault TLS feature disabled")

    @click.command()
    def configure(self) -> None:
        pass  # unchanged

    def enabled_commands(self) -> dict[str, list[dict]]:
        return {
            "init": [{"name": self.group.name, "command": self.tls_group}],
            "init.tls": [{"name": "vault", "command": self.ca_group}],
            "init.tls.vault": [
                {"name": "enable", "command": self.enable_cmd},
                {"name": "disable", "command": self.disable_cmd},
                {"name": "configure", "command": self.configure},
            ],
        }
