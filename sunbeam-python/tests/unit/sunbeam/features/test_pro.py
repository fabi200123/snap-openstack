# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock

import pytest

from sunbeam.core.common import ResultType
from sunbeam.core.juju import TimeoutException
from sunbeam.core.terraform import TerraformException
from sunbeam.features.pro.feature import (
    DisableUbuntuProApplicationStep,
    EnableUbuntuProApplicationStep,
)


@pytest.fixture(autouse=True)
def mock_run_sync(mocker):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()

    def run_sync(coro):
        return loop.run_until_complete(coro)

    mocker.patch("sunbeam.features.pro.feature.run_sync", run_sync)
    yield
    loop.close()


class TestEnableUbuntuProApplicationStep(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.tfhelper = Mock()
        self.jhelper = AsyncMock()
        self.manifest = Mock()
        self.model = "test-model"
        self.token = "TOKENFORTESTING"
        self.step = EnableUbuntuProApplicationStep(
            self.client,
            self.tfhelper,
            self.jhelper,
            self.manifest,
            self.token,
            self.model,
        )

    def test_is_skip(self):
        result = self.step.is_skip()
        assert result.result_type == ResultType.COMPLETED

    def test_has_prompts(self):
        assert not self.step.has_prompts()

    def test_enable(self):
        result = self.step.run()
        self.tfhelper.update_tfvars_and_apply_tf.assert_called_with(
            self.client,
            self.manifest,
            tfvar_config=None,
            override_tfvars={"machine-model": self.model, "token": self.token},
        )
        self.jhelper.wait_application_ready.assert_called_once()
        assert result.result_type == ResultType.COMPLETED

    def test_enable_tf_apply_failed(self):
        self.tfhelper.update_tfvars_and_apply_tf.side_effect = TerraformException(
            "apply failed..."
        )

        result = self.step.run()

        self.tfhelper.update_tfvars_and_apply_tf.assert_called_once()
        assert result.result_type == ResultType.FAILED
        assert result.message == "apply failed..."

    def test_enable_waiting_timed_out(self):
        self.jhelper.wait_application_ready.side_effect = TimeoutException("timed out")

        result = self.step.run()

        self.jhelper.wait_application_ready.assert_called_once()
        assert result.result_type == ResultType.FAILED
        assert result.message == "timed out"


class TestDisableUbuntuProApplicationStep(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.tfhelper = Mock()
        self.jhelper = AsyncMock()
        self.manifest = Mock()
        self.step = DisableUbuntuProApplicationStep(
            self.client, self.tfhelper, self.manifest
        )

    def test_is_skip(self):
        result = self.step.is_skip()
        assert result.result_type == ResultType.COMPLETED

    def test_has_prompts(self):
        assert not self.step.has_prompts()

    def test_disable(self):
        result = self.step.run()
        self.tfhelper.update_tfvars_and_apply_tf.assert_called_with(
            self.client,
            self.manifest,
            tfvar_config=None,
            override_tfvars={"token": ""},
        )
        assert result.result_type == ResultType.COMPLETED

    def test_disable_tf_apply_failed(self):
        self.tfhelper.update_tfvars_and_apply_tf.side_effect = TerraformException(
            "apply failed..."
        )

        result = self.step.run()

        self.tfhelper.update_tfvars_and_apply_tf.assert_called_once()
        assert result.result_type == ResultType.FAILED
        assert result.message == "apply failed..."
