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
MICROOVN_UNIT_TIMEOUT = (
    1200
)


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
    """Deploy Microovn application using Terraform."""

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
            "Deploy Microovn",
            "Deploying MicroOVN",
            refresh,
        )

    def get_application_timeout(self) -> int:
        """Return application timeout in seconds."""
        return MICROOVN_APP_TIMEOUT

    def extra_tfvars(self) -> dict:
        """Extra terraform vars to pass to terraform apply."""
        tfvars: dict[str, Any] = {
            "gateway_interface": "enp86s0"
        }

        return tfvars


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

    _CONFIG = CONFIG_DISKS_KEY

    def __init__(
        self,
        client: Client,
        name: str,
        jhelper: JujuHelper,
        model: str,
        manifest: Manifest | None = None,
        accept_defaults: bool = False,
    ):
        super().__init__("Configure MicroCeph storage", "Configuring MicroCeph storage")
        self.client = client
        self.node_name = name
        self.jhelper = jhelper
        self.model = model
        self.manifest = manifest
        self.accept_defaults = accept_defaults
        self.variables: dict = {}
        self.machine_id = ""
        self.disks = ""
        self.unpartitioned_disks: list[str] = []
        self.osd_disks: list[str] = []

    def microceph_config_questions(self):
        """Return questions for configuring microceph."""
        disks_str = None
        if len(self.unpartitioned_disks) > 0:
            disks_str = ",".join(self.unpartitioned_disks)

        questions = microovn_questions()
        # Specialise question with local disk information.
        questions["osd_devices"].default_value = disks_str
        return questions

    def get_all_disks(self) -> None:
        """Get all disks from microceph unit."""
        try:
            node = self.client.cluster.get_node_info(self.node_name)
            self.machine_id = str(node.get("machineid"))
            unit = self.jhelper.get_unit_from_machine(
                APPLICATION, self.machine_id, self.model
            )
            osd_disks_dict, unpartitioned_disks_dict = list_disks(
                self.jhelper, self.model, unit
            )
            self.unpartitioned_disks = [
                disk.get("path") for disk in unpartitioned_disks_dict
            ]
            self.osd_disks = [disk.get("path") for disk in osd_disks_dict]
            LOG.debug(f"Unpartitioned disks: {self.unpartitioned_disks}")
            LOG.debug(f"OSD disks: {self.osd_disks}")

        except (UnitNotFoundException, ActionFailedException) as e:
            LOG.debug(str(e))
            raise SunbeamException("Unable to list disks")

    def prompt(
        self,
        console: Console | None = None,
        display_question_description: bool = False,
    ) -> None:
        """Determines if the step can take input from the user.

        Prompts are used by Steps to gather the necessary input prior to
        running the step. Steps should not expect that the prompt will be
        available and should provide a reasonable default where possible.
        """
        self.get_all_disks()
        self.variables = questions.load_answers(self.client, self._CONFIG)
        self.variables.setdefault("microceph_config", {})
        self.variables["microceph_config"].setdefault(
            self.node_name, {"osd_devices": None}
        )

        # Set defaults
        if self.manifest and self.manifest.core.config.microceph_config:
            microceph_config = self.manifest.core.config.model_dump(by_alias=True)[
                "microceph_config"
            ]
        else:
            microceph_config = {}
        microceph_config.setdefault(self.node_name, {"osd_devices": None})

        # Preseed can have osd_devices as list. If so, change to comma separated str
        osd_devices = microceph_config.get(self.node_name, {}).get("osd_devices")
        if isinstance(osd_devices, list):
            osd_devices_str = ",".join(osd_devices)
            microceph_config[self.node_name]["osd_devices"] = osd_devices_str

        microceph_config_bank = questions.QuestionBank(
            questions=self.microceph_config_questions(),
            console=console,  # type: ignore
            preseed=microceph_config.get(self.node_name),
            previous_answers=self.variables.get("microceph_config", {}).get(
                self.node_name
            ),
            accept_defaults=self.accept_defaults,
            show_hint=display_question_description,
        )
        # Microceph configuration
        self.disks = microceph_config_bank.osd_devices.ask()
        self.variables["microceph_config"][self.node_name]["osd_devices"] = self.disks

        LOG.debug(self.variables)
        questions.write_answers(self.client, self._CONFIG, self.variables)

    def has_prompts(self) -> bool:
        """Returns true if the step has prompts that it can ask the user.

        :return: True if the step can ask the user for prompts,
                 False otherwise
        """
        return True

    def is_skip(self, status: Status | None = None) -> Result:
        """Determines if the step should be skipped or not.

        :return: ResultType.SKIPPED if the Step should be skipped,
                ResultType.COMPLETED or ResultType.FAILED otherwise
        """
        if not self.disks:
            LOG.debug(
                "Skipping ConfigureMicrocephOSDStep as no osd devices are selected"
            )
            return Result(ResultType.SKIPPED)

        # Remove any disks that are already added
        disks_to_add = set(self.disks.split(",")).difference(self.osd_disks)
        self.disks = ",".join(disks_to_add)
        if not self.disks:
            LOG.debug("Skipping ConfigureMicrocephOSDStep as devices are already added")
            return Result(ResultType.SKIPPED)

        return Result(ResultType.COMPLETED)

    def run(self, status: Status | None = None) -> Result:
        """Configure local disks on microceph."""
        failed = False
        try:
            unit = self.jhelper.get_unit_from_machine(
                APPLICATION, self.machine_id, self.model
            )
            LOG.debug(f"Running action add-osd on {unit}")
            action_result = self.jhelper.run_action(
                unit,
                self.model,
                "add-osd",
                action_params={
                    "device-id": self.disks,
                },
            )
            LOG.debug(f"Result after running action add-osd: {action_result}")
        except UnitNotFoundException as e:
            message = f"Microceph Adding disks {self.disks} failed: {str(e)}"
            failed = True
        except ActionFailedException as e:
            message = f"Microceph Adding disks {self.disks} failed: {str(e)}"
            LOG.debug(message)
            try:
                error = ast.literal_eval(str(e))
                results = ast.literal_eval(error.get("result"))
                for result in results:
                    if result.get("status") == "failure":
                        # disk already added to microceph, ignore the error
                        if "entry already exists" in result.get("message"):
                            disk = result.get("spec")
                            LOG.debug(f"Disk {disk} already added")
                            continue
                        else:
                            failed = True
            except Exception as ex:
                LOG.debug(f"Exception in eval action output: {str(ex)}")
                return Result(ResultType.FAILED, message)

        if failed:
            return Result(ResultType.FAILED, message)

        return Result(ResultType.COMPLETED)
