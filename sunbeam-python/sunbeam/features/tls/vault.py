# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import typing
from pathlib import Path

import click
import yaml
from packaging.version import Version
from rich.console import Console
from rich.table import Table

from sunbeam.clusterd.service import (
    ConfigItemNotFoundException,
)
from sunbeam.core import questions
from sunbeam.core.common import (
    FORMAT_TABLE,
    FORMAT_YAML,
    read_config,
    run_plan,
    str_presenter,
    SunbeamException,
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
from sunbeam.features.interface.utils import (
    validate_ca_certificate,
    validate_ca_chain,
)
from sunbeam.features.interface.v1.openstack import (
    TerraformPlanLocation,
    WaitForApplicationsStep,
)
from sunbeam.features.tls.ca import (
    CaTlsFeatureConfig,
    CaTlsFeature,
    ConfigureCAStep,
)
from sunbeam.features.tls.common import (
    INGRESS_CHANGE_APPLICATION_TIMEOUT,
    certificate_questions,
    get_outstanding_certificate_requests,
)
from sunbeam.utils import click_option_show_hints, pass_method_obj

CERTIFICATE_FEATURE_KEY = "TlsProvider"
CA_APP_NAME = "manual-tls-certificates"
LOG = logging.getLogger(__name__)
console = Console()
ConfigType = typing.TypeVar("ConfigType", bound=FeatureConfig)


class VaultTlsFeature(CaTlsFeature):
    version = Version("0.0.1")

    name = "tls.vault"
    tf_plan_location = TerraformPlanLocation.SUNBEAM_TERRAFORM_REPO

    def config_type(self) -> type | None:
        """Return the config type for the feature."""
        return CaTlsFeatureConfig

    def default_software_overrides(self) -> SoftwareConfig:
        """Feature software configuration."""
        return SoftwareConfig(
            charms={"manual-tls-certificates": CharmManifest(
                channel="1/edge")}
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

    @click.command()
    @click.option(
        "--endpoint",
        "endpoints",
        multiple=True,
        default=["public"],
        type=click.Choice(["public", "internal", "rgw"], case_sensitive=False),
        help="Specify endpoints to apply tls.",
    )
    @click.option(
        "--ca-chain",
        required=True,
        type=str,
        callback=validate_ca_chain,
        help="Base64 encoded CA Chain certificate",
    )
    @click.option(
        "--ca",
        required=True,
        type=str,
        callback=validate_ca_certificate,
        help="Base64 encoded CA certificate",
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
        """Enable TLS Vault feature."""
        # Check if vault is enabled
        name = "vault"

        self.pre_enable(deployment, CaTlsFeatureConfig, show_hints)
        self.enable_feature(
            deployment,
            CaTlsFeatureConfig(ca=ca, ca_chain=ca_chain, endpoints=endpoints),
            show_hints,
        )

    @click.command()
    @click_option_show_hints
    @pass_method_obj
    def disable_cmd(self, deployment: Deployment, show_hints: bool):
        """Disable CA feature."""
        self.disable_feature(deployment, show_hints)
        console.print("TLS Vault feature disabled")

    def set_application_names(self, deployment: Deployment) -> list:
        """Application names handled by the terraform plan."""
        return ["manual-tls-certificates"]

    def set_tfvars_on_enable(
        self, deployment: Deployment, config: CaTlsFeatureConfig
    ) -> dict:
        """Set terraform variables to enable the application."""
        tfvars: dict[str, str | bool] = {
            "traefik-to-tls-provider": CA_APP_NAME}
        if "public" in config.endpoints:
            tfvars.update({"enable-tls-for-public-endpoint": True})
        if "internal" in config.endpoints:
            tfvars.update({"enable-tls-for-internal-endpoint": True})
        if "rgw" in config.endpoints:
            tfvars.update({"enable-tls-for-rgw-endpoint": True})

        return tfvars

    def set_tfvars_on_disable(self, deployment: Deployment) -> dict:
        """Set terraform variables to disable the application."""
        tfvars: dict[str, None | str | bool] = {
            "traefik-to-tls-provider": None}
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

    @click.group()
    def tls_group(self) -> None:
        """Manage TLS."""

    @click.group()
    def ca_group(self) -> None:
        """Manage CA."""

    @click.command()
    @click.option(
        "--format",
        type=click.Choice([FORMAT_TABLE, FORMAT_YAML]),
        default=FORMAT_TABLE,
        help="Output format",
    )
    @pass_method_obj
    def list_outstanding_csrs(self, deployment: Deployment,
                              format: str) -> None:
        """List outstanding CSRs."""
        app = CA_APP_NAME
        model = OPENSTACK_MODEL
        action_cmd = "get-outstanding-certificate-requests"
        jhelper = JujuHelper(deployment.get_connected_controller())
        try:
            action_result = get_outstanding_certificate_requests(
                app, model, jhelper)
        except LeaderNotFoundException as e:
            LOG.debug(f"Unable to get {app} leader to print CSRs")
            raise click.ClickException(str(e))
        except ActionFailedException as e:
            LOG.debug(f"Running action {action_cmd} failed")
            raise click.ClickException(str(e))

        LOG.debug(f"Result from action {action_cmd}: {action_result}")
        if action_result.get("return-code", 0) > 1:
            raise click.ClickException(
                "Unable to get outstanding certificate requests from CA"
            )

        certs_to_process = json.loads(action_result.get("result", "[]"))
        csrs = {
            unit: csr
            for record in certs_to_process
            if (unit := record.get("unit_name")) and (csr := record.get("csr"))
        }

        if format == FORMAT_TABLE:
            table = Table()
            table.add_column("Unit name")
            table.add_column("CSR")
            for unit, csr in csrs.items():
                table.add_row(unit, csr)
            console.print(table)
        elif format == FORMAT_YAML:
            yaml.add_representer(str, str_presenter)
            console.print(yaml.dump(csrs))

    @click.command()
    @click.option(
        "-m",
        "--manifest",
        "manifest_path",
        help="Manifest file.",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
    )
    @click_option_show_hints
    @pass_method_obj
    def configure(
        self,
        deployment: Deployment,
        manifest_path: Path | None = None,
        show_hints: bool = False,
    ) -> None:
        """Configure Unit certs."""
        client = deployment.get_client()
        manifest = deployment.get_manifest(manifest_path)
        preseed = {}
        if (ca := manifest.get_feature(
             self.name.split(".")[-1])) and ca.config:
            preseed = ca.config.model_dump(by_alias=True)
        model = OPENSTACK_MODEL
        apps_to_monitor = ["traefik", "traefik-public", "keystone"]
        if client.cluster.list_nodes_by_role("storage"):
            apps_to_monitor.append("traefik-rgw")

        try:
            config = read_config(client, CERTIFICATE_FEATURE_KEY)
        except ConfigItemNotFoundException:
            config = {}
        ca = config.get("ca")
        ca_chain = config.get("chain")

        if ca is None or ca_chain is None:
            raise click.ClickException("CA and CA Chain not configured")

        jhelper = JujuHelper(deployment.get_connected_controller())
        plan = [
            AddManifestStep(client, manifest_path),
            ConfigureCAStep(
                client,
                jhelper,
                ca,
                ca_chain,
                deployment_preseed=preseed,
            ),
            # On ingress change, the keystone takes time to update the service
            # endpoint, update the identity-service relation data on every
            # related application.
            WaitForApplicationsStep(
                jhelper, apps_to_monitor, model,
                INGRESS_CHANGE_APPLICATION_TIMEOUT
            ),
        ]
        run_plan(plan, console, show_hints)
        click.echo("CA certs configured")

    def enabled_commands(self) -> dict[str, list[dict]]:
        """Dict of clickgroup along with commands.

        Return the commands available once the feature is enabled.
        """
        return {
            "init": [{"name": self.group.name, "command": self.tls_group}],
            "init.tls": [{"name": "vault", "command": self.ca_group}],
            "init.tls.vault": [
                {"name": "unit_certs", "command": self.configure},
                {
                    "name": "list_outstanding_csrs",
                    "command": self.list_outstanding_csrs,
                },
            ],
        }

    def is_vault_application_active(self, jhelper: JujuHelper) -> bool:
        """Check if Vault application is active."""
        model = run_sync(jhelper.get_model(OPENSTACK_MODEL))
        try:
            application = run_sync(jhelper.get_application("vault", model))
        except SunbeamException:
            raise click.ClickException(
                "Cannot enable TLS Vault as Vault is not enabled."
                "Enable Vault first.")
        status = application.status
        run_sync(model.disconnect())
        if status == "active":
            return True
        elif status == "blocked":
            raise click.ClickException(
                "Vault application is blocked. Initialize and authorize "
                "Vault first.")
        return False

    def is_tls_ca_enabled(self, jhelper: JujuHelper) -> bool:
        """Check if Vault application is active."""
        model = run_sync(jhelper.get_model(OPENSTACK_MODEL))
        try:
            _ = run_sync(jhelper.get_application(
                "manual-tls-certificates", model))
        except SunbeamException:
            return True
        run_sync(model.disconnect())
        return False

    def pre_enable(
        self, deployment: Deployment, config: ConfigType, show_hints: bool
    ) -> None:
        """Handler to perform tasks before enabling the feature."""
        super().pre_enable(deployment, config, show_hints)
        jhelper = JujuHelper(deployment.get_connected_controller())
        if not self.is_vault_application_active(jhelper):
            raise click.ClickException(
                "Cannot enable TLS Vault as Vault is not enabled."
                "Enable Vault first."
            )
        if not self.is_tls_ca_enabled(jhelper):
            raise click.ClickException(
                "Cannot enable TLS Vault as TLS CA is already enabled."
            )
