# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

import sunbeam.features.interface.v1.openstack as openstack
from sunbeam.core.common import ResultType
from sunbeam.core.juju import TimeoutException
from sunbeam.core.terraform import TerraformException


@pytest.fixture(autouse=True)
def mock_run_sync(mocker):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()

    def run_sync(coro):
        return loop.run_until_complete(coro)

    mocker.patch("sunbeam.features.interface.v1.openstack.run_sync", run_sync)
    yield
    loop.close()


@pytest.fixture()
def jhelper():
    yield AsyncMock()


@pytest.fixture()
def tfhelper():
    yield Mock(path=Path())


@pytest.fixture()
def osfeature():
    with patch(
        "sunbeam.features.interface.v1.openstack.OpenStackControlPlaneFeature"
    ) as p:
        yield p


@pytest.fixture()
def manifest():
    yield Mock()


@pytest.fixture()
def deployment():
    yield Mock()


class TestEnableOpenStackApplicationStep:
    def test_run(self, deployment, tfhelper, jhelper, osfeature):
        step = openstack.EnableOpenStackApplicationStep(
            deployment, Mock(), tfhelper, jhelper, osfeature
        )
        result = step.run()

        tfhelper.update_tfvars_and_apply_tf.assert_called_once()
        jhelper.wait_until_desired_status.assert_called_once()
        assert result.result_type == ResultType.COMPLETED

    def test_run_tf_apply_failed(self, deployment, jhelper, tfhelper, osfeature):
        tfhelper.update_tfvars_and_apply_tf.side_effect = TerraformException(
            "apply failed..."
        )

        step = openstack.EnableOpenStackApplicationStep(
            deployment, Mock(), tfhelper, jhelper, osfeature
        )
        result = step.run()

        tfhelper.update_tfvars_and_apply_tf.assert_called_once()
        jhelper.wait_until_desired_status.assert_not_called()
        assert result.result_type == ResultType.FAILED
        assert result.message == "apply failed..."

    def test_run_waiting_timed_out(self, deployment, jhelper, tfhelper, osfeature):
        jhelper.wait_until_desired_status.side_effect = TimeoutException("timed out")

        step = openstack.EnableOpenStackApplicationStep(
            deployment, Mock(), tfhelper, jhelper, osfeature
        )
        result = step.run()

        tfhelper.update_tfvars_and_apply_tf.assert_called_once()
        jhelper.wait_until_desired_status.assert_called_once()
        assert result.result_type == ResultType.FAILED
        assert result.message == "timed out"


class TestDisableOpenStackApplicationStep:
    def test_run(self, deployment, tfhelper, jhelper, osfeature):
        step = openstack.DisableOpenStackApplicationStep(
            deployment, tfhelper, jhelper, osfeature
        )
        result = step.run()

        tfhelper.update_tfvars_and_apply_tf.assert_called_once()
        assert result.result_type == ResultType.COMPLETED

    def test_run_tf_apply_failed(self, deployment, tfhelper, jhelper, osfeature):
        tfhelper.update_tfvars_and_apply_tf.side_effect = TerraformException(
            "apply failed..."
        )

        step = openstack.DisableOpenStackApplicationStep(
            deployment, tfhelper, jhelper, osfeature
        )
        result = step.run()

        tfhelper.update_tfvars_and_apply_tf.assert_called_once()
        assert result.result_type == ResultType.FAILED
        assert result.message == "apply failed..."

    def test_run_waiting_timed_out(self, deployment, tfhelper, jhelper, osfeature):
        jhelper.wait_application_gone.side_effect = TimeoutException("timed out")

        step = openstack.DisableOpenStackApplicationStep(
            deployment, tfhelper, jhelper, osfeature
        )
        result = step.run()

        tfhelper.update_tfvars_and_apply_tf.assert_called_once()
        jhelper.wait_application_gone.assert_called_once()
        assert result.result_type == ResultType.FAILED
        assert result.message == "timed out"


class TestUpgradeOpenStackApplicationStep:
    def test_run(
        self,
        deployment,
        tfhelper,
        jhelper,
        osfeature,
    ):
        jhelper.get_model_status_full.return_value = {
            "applications": {
                "keystone": {
                    "charm": "ch:amd64/jammy/keystone-k8s-148",
                    "charm-channel": "2023.2/stable",
                }
            }
        }

        step = openstack.UpgradeOpenStackApplicationStep(
            deployment, tfhelper, jhelper, osfeature
        )
        result = step.run()

        tfhelper.update_partial_tfvars_and_apply_tf.assert_called_once()
        jhelper.wait_until_desired_status.assert_called_once()
        assert result.result_type == ResultType.COMPLETED

    def test_run_tf_apply_failed(self, deployment, tfhelper, jhelper, osfeature):
        tfhelper.update_partial_tfvars_and_apply_tf.side_effect = TerraformException(
            "apply failed..."
        )

        jhelper.get_model_status_full.return_value = {
            "applications": {
                "keystone": {
                    "charm": "ch:amd64/jammy/keystone-k8s-148",
                    "charm-channel": "2023.2/stable",
                }
            }
        }

        step = openstack.UpgradeOpenStackApplicationStep(
            deployment, tfhelper, jhelper, osfeature
        )
        result = step.run()

        tfhelper.update_partial_tfvars_and_apply_tf.assert_called_once()
        jhelper.wait_until_desired_status.assert_not_called()
        assert result.result_type == ResultType.FAILED
        assert result.message == "apply failed..."

    def test_run_waiting_timed_out(self, deployment, tfhelper, jhelper, osfeature):
        jhelper.wait_until_desired_status.side_effect = TimeoutException("timed out")

        jhelper.get_model_status_full.return_value = {
            "applications": {
                "keystone": {
                    "charm": "ch:amd64/jammy/keystone-k8s-148",
                    "charm-channel": "2023.2/stable",
                }
            }
        }

        step = openstack.UpgradeOpenStackApplicationStep(
            deployment, tfhelper, jhelper, osfeature
        )
        result = step.run()

        tfhelper.update_partial_tfvars_and_apply_tf.assert_called_once()
        jhelper.wait_until_desired_status.assert_called_once()
        assert result.result_type == ResultType.FAILED
        assert result.message == "timed out"
