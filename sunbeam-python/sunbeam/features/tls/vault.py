# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import typing
from pathlib import Path

import click
import pydantic
import yaml
from packaging.version import Version
from rich.console import Console
from rich.status import Status
from rich.table import Table

from sunbeam.clusterd.client import Client
from sunbeam.clusterd.service import (
    ConfigItemNotFoundException,
)
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
    SunbeamException,
)
from sunbeam.core.deployment import Deployment
from sunbeam.core.juju import (
    ActionFailedException,
    JujuException,
    JujuHelper,
    LeaderNotFoundException,
    TimeoutException,
    run_sync,
)
from sunbeam.core.manifest import (
    AddManifestStep,
    FeatureConfig,
)
from sunbeam.core.openstack import OPENSTACK_MODEL
from sunbeam.features.interface.utils import (
    encode_base64_as_string,
    get_subject_from_csr,
    is_certificate_valid,
    validate_ca_certificate,
    validate_ca_chain,
)
from sunbeam.features.interface.v1.openstack import (
    TerraformPlanLocation,
    WaitForApplicationsStep,
)
from sunbeam.features.tls.common import (
    INGRESS_CHANGE_APPLICATION_TIMEOUT,
    TlsFeature,
    TlsFeatureConfig,
    certificate_questions,
    external_hostname_questions,
    get_outstanding_certificate_requests,
)
from sunbeam.features.vault.feature import (
    VaultHelper,
    VaultCommandFailedException,
)
from sunbeam.utils import click_option_show_hints, pass_method_obj

CERTIFICATE_FEATURE_KEY = "TlsProvider"
CA_APP_NAME = "vault"
LOG = logging.getLogger(__name__)
console = Console()
ConfigType = typing.TypeVar("ConfigType", bound=FeatureConfig)


class _Certificate(pydantic.BaseModel):
    certificate: str


class VaultTlsFeatureConfig(TlsFeatureConfig):
    certificates: dict[str, _Certificate] = {}
    external_hostname: dict[str, str] = {}


class ConfigureVaultCAStep(BaseStep):
    """Configure CA certificates."""

    _CONFIG = "FeatureCACertificatesConfig"

    def __init__(
        self,
        client: Client,
        jhelper: JujuHelper,
        ca_cert: str,
        ca_chain: str,
        deployment_preseed: dict | None = None,
    ):
        super().__init__("Configure CA certs", "Configuring CA certificates")
        self.client = client
        self.jhelper = jhelper
        self.ca_cert = ca_cert
        self.ca_chain = ca_chain
        self.preseed = deployment_preseed or {}
        self.app = "manual-tls-certificates"
        self.model = OPENSTACK_MODEL
        self.process_certs: dict = {}

    def has_prompts(self) -> bool:
        """Returns true if the step has prompts that it can ask the user."""
        return True

    def prompt(
        self,
        console: Console | None = None,
        show_hint: bool = False,
    ) -> None:
        """Prompt the user for certificates.

        Prompts the user for required information for cert configuration.

        :param console: the console to prompt on
        :type console: rich.console.Console (Optional)
        """
        action_cmd = "get-outstanding-certificate-requests"
        # let exception propagate, since they are SunbeamException
        # they will be caught cleanly
        action_result = get_outstanding_certificate_requests(
            self.app, self.model, self.jhelper
        )

        LOG.debug(f"Result from action {action_cmd}: {action_result}")
        if action_result.get("return-code", 0) > 1:
            raise click.ClickException(
                "Unable to get outstanding certificate requests from CA"
            )

        certs_to_process = json.loads(action_result.get("result", "[]"))
        if not certs_to_process:
            LOG.debug("No outstanding certificates to process")
            return

        variables = questions.load_answers(self.client, self._CONFIG)
        variables.setdefault("certificates", {})
        self.preseed.setdefault("certificates", {})

        for record in certs_to_process:
            unit_name = record.get("unit_name")
            csr = record.get("csr")
            app = record.get("application_name")
            relation_id = record.get("relation_id")
            if not unit_name:
                # Until manual-tls-certificates charm supports unit_name
                # in its relation data, will use a hardcoded "Vault" value.
                unit_name = "Vault"

            # Each unit can have multiple CSRs
            subject = get_subject_from_csr(csr)
            if not subject:
                raise click.ClickException(
                    f"Not a valid CSR for unit {unit_name}")

            # 1) If the manifest pre-seed has a Base64-encoded PEM for this subject, decode & use it:
            import base64
            pre_raw = self.preseed.get("certificates", {}).get(subject, {}).get("certificate")
            if pre_raw:
                try:
                    # decode the entire PEM (including headers)
                    pre_cert = base64.b64decode(pre_raw).decode("utf-8")
                except Exception as e:
                    raise click.ClickException(
                        f"Failed to Base64-decode pre-seeded certificate for {subject!r}: {e}"
                    )

                # validate the decoded PEM
                if not is_certificate_valid(pre_cert):
                    raise click.ClickException(
                        f"Pre-seeded certificate for {subject!r} is invalid after decoding"
                    )

                # accept it without prompting
                self.process_certs[subject] = {
                    "app": record["application_name"],
                    "unit": unit_name,
                    "relation_id": record["relation_id"],
                    "csr": record["csr"],
                    "certificate": pre_cert,
                }
                variables.setdefault("certificates", {}).setdefault(subject, {})[
                    "certificate"
                ] = pre_cert
                continue

            cert_questions = certificate_questions(unit_name, subject)
            certificates_bank = questions.QuestionBank(
                questions=cert_questions,
                console=console,
                preseed=self.preseed.get("certificates", {}).get(subject),
                previous_answers=variables.get(
                    "certificates", {}).get(subject),
                show_hint=show_hint,
            )
            cert = certificates_bank.certificate.ask()
            if not cert or not is_certificate_valid(cert):
                raise click.ClickException("Not a valid certificate")

            self.process_certs[subject] = {
                "app": app,
                "unit": unit_name,
                "relation_id": relation_id,
                "csr": csr,
                "certificate": cert,
            }
            variables["certificates"].setdefault(subject, {})
            variables["certificates"][subject]["certificate"] = cert

        questions.write_answers(self.client, self._CONFIG, variables)

    def is_skip(self, status: Status | None = None) -> Result:
        """Determines if the step should be skipped or not.

        :return: ResultType.SKIPPED if the Step should be skipped,
                ResultType.COMPLETED or ResultType.FAILED otherwise
        """
        return Result(ResultType.COMPLETED)

    def run(self, status: Status | None = None) -> Result:
        """Run configure steps."""
        action_cmd = "provide-certificate"
        try:
            unit = run_sync(self.jhelper.get_leader_unit(self.app, self.model))
        except LeaderNotFoundException as e:
            LOG.debug(f"Unable to get {self.app} leader")
            return Result(ResultType.FAILED, str(e))

        LOG.debug(f"Process certs: {self.process_certs}")
        for subject, request in self.process_certs.items():
            csr = request.get("csr")
            csr = encode_base64_as_string(csr)
            if not csr:
                return Result(ResultType.FAILED)

            action_params = {
                "certificate": request.get("certificate"),
                "ca-chain": self.ca_cert,
                "ca-certificate": self.ca_cert,
                "certificate-signing-request": str(csr),
            }

            LOG.debug(f"Running action {action_cmd}")
            try:
                action_result = run_sync(
                    self.jhelper.run_action(
                        unit, self.model, action_cmd, action_params)
                )
            except ActionFailedException as e:
                LOG.debug(f"Running action {action_cmd} on {unit}")
                return Result(ResultType.FAILED, str(e))

            LOG.debug(f"Result from action {action_cmd}: {action_result}")
            if action_result.get("return-code", 0) > 1:
                return Result(
                    ResultType.FAILED,
                    f"Action {action_cmd} on {unit} returned error"
                )

        return Result(ResultType.COMPLETED)


class VaultTlsFeature(TlsFeature):
    version = Version("0.0.1")

    name = "tls.vault"
    tf_plan_location = TerraformPlanLocation.SUNBEAM_TERRAFORM_REPO

    @click.group()
    def vault_group(self) -> None:
        """Manage CA (HashiCorp Vault)."""

    def config_type(self) -> type | None:
        """Return the config type for the feature."""
        return VaultTlsFeatureConfig

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
        external_question_bank = questions.QuestionBank(
            questions=external_hostname_questions("traefik", "", ["public", "internal", "rgw"]),
            console=console,
            previous_answers={},
        )
        external_content = questions.show_questions(
            external_question_bank,
            section="external_hostname",
            section_description="External hostnames for endpoints",
            comment_out=True,
        )
        return [content, external_content]

    @click.command()
    @click.option(
        "--endpoint",
        "endpoints",
        multiple=True,
        default=["public"],
        type=click.Choice(["public", "internal", "rgw"], case_sensitive=False),
        help="Specify which endpoints to apply TLS for.",
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
        # 1) Pre-enable checks
        self.pre_enable(deployment, VaultTlsFeatureConfig, show_hints)

        # 2) Prompt interactively for each endpoint’s external hostname
        CORE_KEY = "CoreConfig"
        core_vars = questions.load_answers(deployment.get_client(), CORE_KEY)
        core_vars.setdefault("external_hostname", {})

        # Build a QuestionBank only for the endpoints you specified
        qbank = questions.QuestionBank(
            questions=external_hostname_questions("traefik", "", endpoints),
            console=console,
            previous_answers=core_vars["external_hostname"],
            show_hint=show_hints,
        )

        for ep in endpoints:
            # ask the user
            host = getattr(qbank, f"external_hostname_{ep}").ask()
            if not host:
                raise click.ClickException(f"No hostname provided for endpoint '{ep}'")
            core_vars["external_hostname"][ep] = host

        # Persist into CoreConfig
        questions.write_answers(deployment.get_client(), CORE_KEY, core_vars)

        # 3) Validate that all hostnames share a single domain,
        #    and set vault.common_name accordingly BEFORE we enable.
        external_map = {
            ep: core_vars["external_hostname"][ep]
            for ep in endpoints
            if ep in core_vars["external_hostname"]
        }

        if not external_map:
            raise click.ClickException(
                "No external hostnames found for endpoints: " +
                ", ".join(endpoints)
            )
        # extract everything after the first dot
        domains = {h.split(".", 1)[1] for h in external_map.values()}
        if len(domains) != 1:
            raise click.ClickException(
                "All external hostnames must share the same domain, "
                f"but found: {', '.join(external_map.values())}"
            )
        common_domain = domains.pop()

        # connect to Juju and set vault.common_name
        jhelper = JujuHelper(deployment.get_connected_controller())
        model = run_sync(jhelper.get_model(OPENSTACK_MODEL))
        vault_app = run_sync(jhelper.get_application(CA_APP_NAME, model))
        try:
            run_sync(vault_app.set_config({"common_name": common_domain}))
            console.print(f"Set {CA_APP_NAME} common_name = {common_domain}")
        except Exception as e:
            LOG.error(f"Failed to set common_name on {CA_APP_NAME}: {e}")
            raise click.ClickException(f"Could not configure {CA_APP_NAME}: {e}")

        # 4) Finally, enable the Vault TLS feature as usual
        cfg = VaultTlsFeatureConfig(
            ca=ca,
            ca_chain=ca_chain,
            endpoints=endpoints,
            external_hostname=external_map,
        )
        self.enable_feature(deployment, cfg, show_hints)


    @click.command()
    @click_option_show_hints
    @pass_method_obj
    def disable_cmd(self, deployment: Deployment, show_hints: bool):
        """Disable TLS Vault feature."""
        self.disable_feature(deployment, show_hints)
        console.print("TLS Vault feature disabled")

    def set_application_names(self, deployment: Deployment) -> list:
        """Application names handled by the terraform plan."""
        return ["manual-tls-certificates"]

    def set_tfvars_on_enable(
        self, deployment: Deployment, config: VaultTlsFeatureConfig
    ) -> dict:
        """Set terraform variables to enable the application."""
        tfvars: dict[str, str | bool] = {
            "traefik-to-tls-provider": CA_APP_NAME,
            "manual-tls-certificates-channel": "1/edge"}
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
        app = "manual-tls-certificates"
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
        # Until Manual-TLS-Certificates charm supports unit_name in its relation data,
        # we will use a hardcoded "Vault" value for unit_name.
        csrs = {
            unit_name: csr
            for record in certs_to_process
            if (unit_name := "Vault") and (
                csr := record.get("csr"))
        }

        if format == FORMAT_TABLE:
            table = Table()
            table.add_column("Application")
            table.add_column("CSR")
            for unit_name, csr in csrs.items():
                table.add_row(unit_name, csr)
            console.print(table)
        elif format == FORMAT_YAML:
            yaml.add_representer(str, str_presenter)
            console.print(yaml.dump(csrs))

    @click.command()
    @click.option(
        "-m", "--manifest", "manifest_path",
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
        if (vault_feat := manifest.get_feature(self.name.split(".")[-1])) and vault_feat.config:
            # vault_feat.config is VaultTlsFeatureConfig
            # its .certificates is a dict[str, _Certificate]
            for subject, cert_obj in (vault_feat.config.certificates or {}).items():
                # each cert_obj has attribute .certificate (the base64‐PEM string)
                preseed[subject] = {"certificate": cert_obj.certificate}

        model = OPENSTACK_MODEL
        apps_to_monitor = [CA_APP_NAME]

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
            ConfigureVaultCAStep(
                client,
                jhelper,
                ca,
                ca_chain,
                deployment_preseed=preseed,
            ),
            WaitForApplicationsStep(
                jhelper,
                apps_to_monitor,
                model,
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
            "init.tls": [{"name": "vault", "command": self.vault_group}],
            "init.tls.vault": [
                {"name": "unit_certs", "command": self.configure},
                {
                    "name": "list_outstanding_csrs",
                    "command": self.list_outstanding_csrs,
                },
            ],
        }

    def is_vault_application_active(self, jhelper: JujuHelper) -> bool:
        """Check if Vault is deployed, initialized, and authorized."""
        model = run_sync(jhelper.get_model(OPENSTACK_MODEL))
        try:
            leader = run_sync(
                jhelper.get_leader_unit(CA_APP_NAME, OPENSTACK_MODEL)
            )
        except SunbeamException:
            raise click.ClickException(
                "Cannot enable TLS Vault because Vault is not deployed. "
                "Please deploy Vault first."
            )

        vhelper = VaultHelper(jhelper)
        app = run_sync(jhelper.get_application(CA_APP_NAME, model))
        unit = app.units[0] if app.units else None
        if not unit:
            raise click.ClickException(
                "Vault application has no units. "
                "Please deploy Vault first."
            )
        status = unit.workload_status
        message = unit.workload_status_message

        if status == "active":
            return True

        try:
            vault_status = vhelper.get_vault_status(leader)
        except VaultCommandFailedException as e:
            raise click.ClickException(f"Error querying Vault status: {e}")
        except (TimeoutException, JujuException) as e:
            raise click.ClickException(f"Unable to contact Vault: {e}")
        finally:
            run_sync(model.disconnect())

        if not vault_status.get("initialized", False):
            raise click.ClickException(
                "Vault is deployed but uninitialized. "
                "Please run `sunbeam vault init` first."
            )

        if vault_status.get("sealed", True):
            raise click.ClickException(
                "Vault is initialized but still sealed. "
                "Please unseal Vault before proceeding."
            )

        if status == "blocked":
            # TODO: Investigate if this is a bug in vault charm
            # There is a case where after vault unseal, the vault
            # application is still in blocked state, but shows the message
            # "Please initialize Vault or integrate
            # with an auto-unseal provider"
            if "authorize" in message.lower() \
                 or "initialize" in message.lower():
                raise click.ClickException(
                    "Vault is not authorized. Please run "
                    "`sunbeam vault authorize-charm` first."
                )
            raise click.ClickException(f"Vault is blocked: {message}")
        return True

    def _get_relations(self, model: str, endpoints: list[str]) -> list[tuple]:
        """Return model relations for the provided endpoints."""
        relations = []
        model_status = run_sync(self.jhelper.get_model_status(model))
        model_relations = [r.get("key") for r in model_status.get(
            "relations", {})]
        for endpoint in endpoints:
            for relation in model_relations:
                if endpoint in relation:
                    relations.append(tuple(relation.split(" ")))
                    break

        return relations

    def pre_enable(
        self, deployment: Deployment,
        config: VaultTlsFeatureConfig, show_hints: bool
    ) -> None:
        """Handler to perform tasks before enabling the feature."""
        super().pre_enable(deployment, config, show_hints)

        provider_config = self.provider_config(deployment)

        provider = provider_config.get("provider")
        if provider and provider != self.name:
            raise Exception(
                f"Certificate provider already set to {provider!r}")

        jhelper = JujuHelper(deployment.get_connected_controller())
        if not self.is_vault_application_active(jhelper):
            raise click.ClickException(
                "Cannot enable TLS Vault as Vault is not enabled."
                "Enable Vault first."
            )
