# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import ast
import logging
from typing import Any

import tenacity
from rich.console import Console
from rich.status import Status

from sunbeam.clusterd.client import Client
from sunbeam.clusterd.service import NodeNotExistInClusterException
from sunbeam.core import questions
from sunbeam.core.common import (
    BaseStep,
    Result,
    ResultType,
    Role,
    SunbeamException,
    read_config,
)
from sunbeam.core.deployment import Deployment, Networks
from sunbeam.core.juju import (
    ActionFailedException,
    ApplicationNotFoundException,
    JujuHelper,
    LeaderNotFoundException,
    UnitNotFoundException,
)
from sunbeam.core.manifest import Manifest
from sunbeam.core.openstack import DEFAULT_REGION, REGION_CONFIG_KEY
from sunbeam.core.steps import (
    AddMachineUnitsStep,
    DeployMachineApplicationStep,
    DestroyMachineApplicationStep,
    RemoveMachineUnitsStep,
)
from sunbeam.core.terraform import TerraformException, TerraformHelper

LOG = logging.getLogger(__name__)
CONFIG_KEY = "TerraformVarsMicroovnPlan"
CONFIG_DISKS_KEY = "TerraformVarsMicroovn"
APPLICATION = "microovn"
MICROOVN_APP_TIMEOUT = 1200
MICROOVN_UNIT_TIMEOUT = 1200


def microovn_questions():
    return {
        "gateway_interface": questions.PromptQuestion(
            "External gateway interface",
            description=(
                "The interface to use for the external gateway. "
                "This interface will be used to connect to the external network."
            ),
        ),
    }


class DeployMicroOVNApplicationStep(DeployMachineApplicationStep):
    """Deploy MicroOVN application using Terraform."""

    def __init__(
        self,
        deployment: Deployment,
        client: Client,
        tfhelper: TerraformHelper,
        jhelper: JujuHelper,
        manifest: Manifest,
        model: str,
        refresh: bool = False,
    ):
        super().__init__(
            deployment,
            client,
            tfhelper,
            jhelper,
            manifest,
            CONFIG_KEY,
            APPLICATION,
            model,
            "Deploy MicroOVN",
            "Deploying MicroOVN",
            refresh,
        )

    def get_application_timeout(self) -> int:
        """Return application timeout in seconds."""
        return MICROOVN_APP_TIMEOUT

    def extra_tfvars(self) -> dict:
        """Extra terraform vars to pass to terraform apply."""
        network_nodes = self.client.cluster.list_nodes_by_role("network")
        tfvars: dict[str, Any] = {
            "gateway_interface": "enp86s0"
        }

        if network_nodes:
            # retrieve upstream offer URLs for CA, OVN relay, certificates, ovsdb-cms
            openstack_tfhelper = self.deployment.get_tfhelper("openstack-plan")
            openstack_tf_output = openstack_tfhelper.output()

            juju_offers = {
                "ca-offer-url",
                "ovn-relay-offer-url",
                "cert-distributor-offer-url",
                "ovsdb-cms-offer-url",
            }
            for offer in juju_offers:
                if url := openstack_tf_output.get(offer):
                    tfvars[offer] = url

        return tfvars


class ReapplyMicroOVNOptionalIntegrationsStep(DeployMicroOVNApplicationStep):
    """Reapply MicroOVN optional integrations using Terraform."""

    def tf_apply_extra_args(self) -> list[str]:
        """Extra args for terraform apply to reapply only optional CMR integrations."""
        return [
            "-target=juju_integration.microovn-cert-distributor",
            "-target=juju_integration.microovn-certs",
            "-target=juju_integration.microovn-ovsdb-cms",
        ]


class AddMicroOVNUnitsStep(AddMachineUnitsStep):
    """Add Microovn Unit."""

    def __init__(
        self,
        client: Client,
        names: list[str] | str,
        jhelper: JujuHelper,
        model: str,
    ):
        super().__init__(
            client,
            names,
            jhelper,
            CONFIG_KEY,
            APPLICATION,
            model,
            "Add MicroOVN unit",
            "Adding MicroOVN unit to machine",
        )

    def get_unit_timeout(self) -> int:
        """Return unit timeout in seconds."""
        return MICROOVN_UNIT_TIMEOUT


class RemoveMicroOVNUnitsStep(RemoveMachineUnitsStep):
    """Remove Microovn Unit."""

    def __init__(
        self, client: Client, names: list[str] | str, jhelper: JujuHelper, model: str
    ):
        super().__init__(
            client,
            names,
            jhelper,
            CONFIG_KEY,
            APPLICATION,
            model,
            "Remove MicroOVN unit(s)",
            "Removing MicroOVN unit(s) from machine",
        )

    def get_unit_timeout(self) -> int:
        """Return unit timeout in seconds."""
        return MICROOVN_UNIT_TIMEOUT


# TODO: Implement this step
class ConfigureMicroOVNStep(BaseStep):
    """Configure MicroOVN OSD disks."""

