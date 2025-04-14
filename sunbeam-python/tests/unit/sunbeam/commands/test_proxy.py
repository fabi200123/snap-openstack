# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
from unittest.mock import Mock, patch

import pytest

from sunbeam.commands.proxy import PromptForProxyStep
from sunbeam.core.deployment import PROXY_CONFIG_KEY


@pytest.fixture()
def question_bank():
    with patch("sunbeam.commands.proxy.QuestionBank") as p:
        yield p


class TestPromptForProxyStep:
    def test_prompt(self, question_bank):
        deployment = Mock()
        previous_answers = {}
        deployment.get_client().cluster.get_config.return_value = json.dumps(
            previous_answers
        )
        deployment.get_default_proxy_settings.return_value = {}
        question_bank().proxy_required.ask.return_value = False
        expected_write_config = {"proxy": {"proxy_required": False}}

        step = PromptForProxyStep(deployment)
        step.prompt()
        deployment.get_client().cluster.update_config.assert_called_with(
            PROXY_CONFIG_KEY, json.dumps(expected_write_config)
        )

    def test_prompt_with_previous_answers(self, question_bank):
        deployment = Mock()
        previous_answers = {
            "proxy": {
                "proxy_required": True,
                "http_proxy": "http://squid.internal:3128",
            }
        }
        deployment.get_client().cluster.get_config.return_value = json.dumps(
            previous_answers
        )
        deployment.get_default_proxy_settings.return_value = {}
        question_bank().proxy_required.ask.return_value = True
        question_bank().http_proxy.ask.return_value = "http://squid.internal:3128"
        question_bank().https_proxy.ask.return_value = "http://squid.internal:3128"
        question_bank().no_proxy.ask.return_value = ".example.com"
        expected_write_config = {
            "proxy": {
                "proxy_required": True,
                "http_proxy": "http://squid.internal:3128",
                "https_proxy": "http://squid.internal:3128",
                "no_proxy": ".example.com",
            }
        }

        step = PromptForProxyStep(deployment)
        step.prompt()
        deployment.get_client().cluster.update_config.assert_called_with(
            PROXY_CONFIG_KEY, json.dumps(expected_write_config)
        )
