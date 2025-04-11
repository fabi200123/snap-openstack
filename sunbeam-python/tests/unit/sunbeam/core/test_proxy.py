# Copyright (c) 2025 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from unittest.mock import patch

import pytest

from sunbeam.core.proxy import patch_process_env, should_bypass


def test_patch_process_env_no_proxies():
    """Test patch_process_env with no proxies provided."""
    with patch.dict(os.environ, {}, clear=True):
        patch_process_env({})
        assert os.environ == {}


def test_patch_process_env_with_proxies():
    """Test patch_process_env with valid proxies."""
    proxies = {
        "HTTP_PROXY": "http://proxy.example.com:8080",
        "HTTPS_PROXY": "https://proxy.example.com:8443",
        "NO_PROXY": "localhost,127.0.0.1",
    }
    with patch.dict(os.environ, {}, clear=True):
        patch_process_env(proxies)
        assert os.environ["http_proxy"] == "http://proxy.example.com:8080"
        assert os.environ["https_proxy"] == "https://proxy.example.com:8443"
        assert os.environ["HTTP_PROXY"] == "http://proxy.example.com:8080"
        assert os.environ["HTTPS_PROXY"] == "https://proxy.example.com:8443"
        assert os.environ["no_proxy"] == "localhost,127.0.0.1"
        assert os.environ["NO_PROXY"] == "localhost,127.0.0.1"


def test_patch_process_env_missing_https_proxy():
    """Test patch_process_env when HTTPS_PROXY is missing."""
    proxies = {
        "HTTP_PROXY": "http://proxy.example.com:8080",
        "NO_PROXY": "localhost,127.0.0.1",
    }
    with patch.dict(os.environ, {}, clear=True):
        patch_process_env(proxies)
        assert os.environ["http_proxy"] == "http://proxy.example.com:8080"
        assert os.environ["https_proxy"] == "http://proxy.example.com:8080"
        assert os.environ["HTTP_PROXY"] == "http://proxy.example.com:8080"
        assert os.environ["HTTPS_PROXY"] == "http://proxy.example.com:8080"
        assert os.environ["no_proxy"] == "localhost,127.0.0.1"
        assert os.environ["NO_PROXY"] == "localhost,127.0.0.1"


def test_patch_process_env_missing_http_proxy():
    """Test patch_process_env when HTTP_PROXY is missing."""
    proxies = {
        "HTTPS_PROXY": "https://proxy.example.com:8443",
        "NO_PROXY": "localhost,127.0.0.1",
    }
    with patch.dict(os.environ, {}, clear=True):
        patch_process_env(proxies)
        assert os.environ["http_proxy"] == "https://proxy.example.com:8443"
        assert os.environ["https_proxy"] == "https://proxy.example.com:8443"
        assert os.environ["HTTP_PROXY"] == "https://proxy.example.com:8443"
        assert os.environ["HTTPS_PROXY"] == "https://proxy.example.com:8443"
        assert os.environ["no_proxy"] == "localhost,127.0.0.1"
        assert os.environ["NO_PROXY"] == "localhost,127.0.0.1"


def test_patch_process_env_no_http_or_https_proxy():
    """Test patch_process_env when neither HTTP_PROXY nor HTTPS_PROXY is provided."""
    proxies = {"NO_PROXY": "localhost,127.0.0.1"}
    with patch.dict(os.environ, {}, clear=True):
        patch_process_env(proxies)
        assert os.environ == {}


@pytest.mark.parametrize(
    "no_proxies,endpoint,expected",
    [
        ([], "example.com", False),  # No proxies, should not bypass
        (["example.com"], "example.com", True),  # Exact match
        (["*.example.com"], "sub.example.com", True),  # Wildcard match
        (["192.168.1.0/24"], "192.168.1.5", True),  # IP in subnet
        (["192.168.1.0/24"], "192.168.2.5", False),  # IP not in subnet
        (["example.com"], "other.com", False),  # No match
        (["*.example.com"], "example.com", False),  # Wildcard no match
        (["192.168.1.0/24"], "not-an-ip", False),  # Invalid IP
        (["*example.com"], "myexample.com", True),  # Ends with match
        (["*example.com"], "example.com", True),  # Ends with match exact
        ([".example.com"], "sub.example.com", True),  # Allow all subdomains
        ([".example.com"], "example.com", False),  # Only subdomains allowed
        (["example.com"], "192.168.1.5", False),  # IP not in no_proxy
    ],
)
def test_should_bypass(no_proxies, endpoint, expected):
    assert should_bypass(no_proxies, endpoint) == expected
