# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import logging

from sunbeam.core.common import BaseStep, Result, ResultType, Status
from sunbeam.core.juju import (
    ApplicationNotFoundException,
    JujuHelper,
    JujuWaitException,
    TimeoutException,
    run_sync,
)
from sunbeam.core.manifest import CharmManifest, Manifest
from sunbeam.versions import JUJU_BASE

LOG = logging.getLogger(__name__)
APPLICATION = "tls-operator"
CHARM = "sunbeam-ssc"
CERTIFICATES_APP_TIMEOUT = 1200


class DeployCertificatesProviderApplicationStep(BaseStep):
    """Deploy tls operator application."""

    def __init__(
        self,
        jhelper: JujuHelper,
        manifest: Manifest,
        model: str,
    ):
        super().__init__(
            "Deploy tls operator",
            "Deploying TLS Operator",
        )
        self.jhelper = jhelper
        self.manifest = manifest
        self.model = model
        self.app = APPLICATION

    def is_skip(self, status: Status | None = None) -> Result:
        """Check whether or not to deploy tls operator."""
        model = run_sync(self.jhelper.get_model(self.model))
        try:
            run_sync(self.jhelper.get_application(self.app, model))
        except ApplicationNotFoundException:
            return Result(ResultType.COMPLETED)
        finally:
            run_sync(model.disconnect())
        return Result(ResultType.SKIPPED)

    def run(self, status: Status | None = None) -> Result:
        """Deploy sunbeam clusterd to infra machines."""
        self.update_status(status, "fetching infra machines")
        model = run_sync(self.jhelper.get_model(self.model))
        clusterd_machines = run_sync(self.jhelper.get_machines(model))
        machines = list(clusterd_machines.keys())
        run_sync(model.disconnect())

        if len(machines) == 0:
            return Result(ResultType.FAILED, f"No machines found in {self.model} model")

        # Deploy on first controller machine
        machines = machines[:1]
        self.update_status(status, "deploying application")
        charm_manifest: CharmManifest = self.manifest.core.software.charms[CHARM]
        run_sync(
            self.jhelper.deploy(
                APPLICATION,
                CHARM,
                self.model,
                1,
                channel=charm_manifest.channel,
                revision=charm_manifest.revision,
                to=machines,
                config=charm_manifest.config,
                base=JUJU_BASE,
            )
        )

        apps = run_sync(self.jhelper.get_application_names(self.model))
        try:
            run_sync(
                self.jhelper.wait_until_active(
                    self.model,
                    apps,
                    timeout=CERTIFICATES_APP_TIMEOUT,
                )
            )
        except (JujuWaitException, TimeoutException) as e:
            LOG.warning(str(e))
            return Result(ResultType.FAILED, str(e))

        return Result(ResultType.COMPLETED)
