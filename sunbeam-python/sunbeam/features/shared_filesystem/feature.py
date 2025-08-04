# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import logging

import click
from packaging.version import Version
from rich.console import Console
from rich.status import Status

from sunbeam.core.common import (
    BaseStep,
    Result,
    ResultType,
    run_plan,
)
from sunbeam.core.deployment import Deployment
from sunbeam.core.juju import (
    JujuException,
    JujuHelper,
    JujuStepHelper,
)
from sunbeam.core.manifest import (
    AddManifestStep,
    CharmManifest,
    FeatureConfig,
    SoftwareConfig,
)
from sunbeam.core.terraform import (
    TerraformInitStep,
)
from sunbeam.features.interface.v1.openstack import (
    DisableOpenStackApplicationStep,
    EnableOpenStackApplicationStep,
    OpenStackControlPlaneFeature,
    TerraformPlanLocation,
)
from sunbeam.steps import microceph
from sunbeam.utils import click_option_show_hints, pass_method_obj
from sunbeam.versions import OPENSTACK_CHANNEL

LOG = logging.getLogger(__name__)
console = Console()


class CreateCephNFSOfferStep(BaseStep, JujuStepHelper):
    """Create microceph-ceph-nfs offer using Terraform."""

    def __init__(
        self,
        deployment: Deployment,
        jhelper: JujuHelper,
    ):
        super().__init__(
            f"Create {microceph.NFS_OFFER_NAME} offer",
            f"Creating {microceph.NFS_OFFER_NAME} offer",
        )
        self.model = deployment.openstack_machines_model
        self.jhelper = jhelper

    def is_skip(self, status: Status | None = None) -> Result:
        """Determines if the step should be skipped or not.

        :return: ResultType.SKIPPED if the Step should be skipped,
                ResultType.COMPLETED or ResultType.FAILED otherwise
        """
        if self.jhelper.offer_exists(self.model, microceph.NFS_OFFER_NAME):
            return Result(ResultType.SKIPPED)

        return Result(ResultType.COMPLETED)

    def run(self, status: Status | None = None) -> Result:
        """Apply terraform configuration to deploy microceph-ceph-nfs offer."""
        try:
            self.jhelper.create_offer(
                self.model,
                microceph.APPLICATION,
                microceph.CEPH_NFS_RELATION,
                microceph.NFS_OFFER_NAME,
            )
        except JujuException as e:
            LOG.exception(f"Error creating {microceph.NFS_OFFER_NAME} offer")
            return Result(ResultType.FAILED, str(e))

        return Result(ResultType.COMPLETED)


class RemoveCephNFSOfferStep(BaseStep, JujuStepHelper):
    """Remove microceph-ceph-nfs offer using Terraform."""

    def __init__(
        self,
        deployment: Deployment,
        jhelper: JujuHelper,
    ):
        super().__init__(
            f"Remove {microceph.NFS_OFFER_NAME} offer",
            f"Removing {microceph.NFS_OFFER_NAME} offer",
        )
        self.model = deployment.openstack_machines_model
        self.jhelper = jhelper

    def is_skip(self, status: Status | None = None) -> Result:
        """Determines if the step should be skipped or not.

        :return: ResultType.SKIPPED if the Step should be skipped,
                ResultType.COMPLETED or ResultType.FAILED otherwise
        """
        if not self.jhelper.offer_exists(self.model, microceph.NFS_OFFER_NAME):
            return Result(ResultType.SKIPPED)

        return Result(ResultType.COMPLETED)

    def run(self, status: Status | None = None) -> Result:
        """Execute configuration using terraform."""
        try:
            self.jhelper.remove_offer(self.model, microceph.NFS_OFFER_NAME)
        except JujuException as e:
            LOG.exception(f"Error removing {microceph.NFS_OFFER_NAME} offer")
            return Result(ResultType.FAILED, str(e))

        return Result(ResultType.COMPLETED)


class SharedFilesystemFeature(OpenStackControlPlaneFeature):
    version = Version("0.0.1")

    name = "shared-filesystem"
    tf_plan_location = TerraformPlanLocation.SUNBEAM_TERRAFORM_REPO

    def default_software_overrides(self) -> SoftwareConfig:
        """Feature software configuration."""
        return SoftwareConfig(
            charms={
                "manila-k8s": CharmManifest(channel=OPENSTACK_CHANNEL),
                "manila-cephfs-k8s": CharmManifest(channel=OPENSTACK_CHANNEL),
            }
        )

    def manifest_attributes_tfvar_map(self) -> dict:
        """Manifest attributes terraformvars map."""
        return {
            self.tfplan: {
                "charms": {
                    "manila-k8s": {
                        "channel": "manila-channel",
                        "revision": "manila-revision",
                        "config": "manila-config",
                    },
                    "manila-cephfs-k8s": {
                        "channel": "manila-cephfs-channel",
                        "revision": "manila-cephfs-revision",
                        "config": "manila-cephfs-config",
                    },
                }
            }
        }

    def set_application_names(self, deployment: Deployment) -> list:
        """Application names handled by the terraform plan."""
        apps = [
            "manila",
            "manila-mysql-router",
            "manila-cephfs",
            "manila-cephfs-mysql-router",
        ]

        if self.get_database_topology(deployment) == "multi":
            apps.extend(["manila-mysql"])

        return apps

    def run_enable_plans(
        self, deployment: Deployment, config: FeatureConfig, show_hints: bool
    ):
        """Run the enablement plans."""
        jhelper = JujuHelper(deployment.juju_controller)
        tfhelper = deployment.get_tfhelper(self.tfplan)

        plan: list[BaseStep] = []
        if self.user_manifest:
            plan.append(AddManifestStep(deployment.get_client(), self.user_manifest))

        plan.extend(
            [
                TerraformInitStep(tfhelper),
                EnableOpenStackApplicationStep(
                    deployment,
                    config,
                    tfhelper,
                    jhelper,
                    self,
                ),
            ]
        )

        ceph_nfs_plan = [CreateCephNFSOfferStep(deployment, jhelper)]

        run_plan(ceph_nfs_plan, console, show_hints)
        run_plan(plan, console, show_hints)

        click.echo("Shared Filesystems enabled.")

    def run_disable_plans(self, deployment: Deployment, show_hints: bool):
        """Run the disablement plans."""
        jhelper = JujuHelper(deployment.juju_controller)
        tfhelper = deployment.get_tfhelper(self.tfplan)

        plan = [
            TerraformInitStep(tfhelper),
            DisableOpenStackApplicationStep(deployment, tfhelper, jhelper, self),
        ]

        ceph_nfs_plan = [RemoveCephNFSOfferStep(deployment, jhelper)]

        run_plan(plan, console, show_hints)
        run_plan(ceph_nfs_plan, console, show_hints)

        click.echo("Shared Filesystems disabled.")

    def set_tfvars_on_enable(
        self, deployment: Deployment, config: FeatureConfig
    ) -> dict:
        """Set terraform variables to enable the application."""
        return {
            "enable-manila": True,
            "enable-manila-cephfs": True,
            "enable-ceph-nfs": True,
            **self.add_horizon_plugin_to_tfvars(deployment, "manila"),
        }

    def set_tfvars_on_disable(self, deployment: Deployment) -> dict:
        """Set terraform variables to disable the application."""
        return {
            "enable-manila": False,
            "enable-manila-cephfs": False,
            "enable-ceph-nfs": False,
            **self.remove_horizon_plugin_from_tfvars(deployment, "manila"),
        }

    def set_tfvars_on_resize(
        self, deployment: Deployment, config: FeatureConfig
    ) -> dict:
        """Set terraform variables to resize the application."""
        return {}

    @click.command()
    @click_option_show_hints
    @pass_method_obj
    def enable_cmd(self, deployment: Deployment, show_hints: bool) -> None:
        """Enable Shared Filesystems service."""
        self.enable_feature(deployment, FeatureConfig(), show_hints)

    @click.command()
    @click_option_show_hints
    @pass_method_obj
    def disable_cmd(self, deployment: Deployment, show_hints: bool) -> None:
        """Disable Shared Filesystems service."""
        self.disable_feature(deployment, show_hints)
