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

import ipaddress
import logging
import os
import typing
from collections.abc import Iterable

LOG = logging.getLogger(__name__)


def patch_process_env(proxies: dict[str, str]) -> None:
    """Patch current env with proxies.

    This function will patch the current process environment
    variables with the given proxies if any proxy is set.
    """
    if not proxies:
        return
    db_http_proxy = proxies.get("HTTP_PROXY")
    db_https_proxy = proxies.get("HTTPS_PROXY")
    db_no_proxy = proxies.get("NO_PROXY", "").strip()
    if db_http_proxy is None and db_https_proxy is None:
        LOG.debug("Proxy provided but no http(s)_proxy found")
        return

    if db_https_proxy is None:
        db_https_proxy = db_http_proxy
    if db_http_proxy is None:
        db_http_proxy = db_https_proxy

    db_http_proxy = typing.cast(str, db_http_proxy).strip()
    db_https_proxy = typing.cast(str, db_https_proxy).strip()

    new_env = {}

    new_env["http_proxy"] = db_http_proxy
    new_env["https_proxy"] = db_https_proxy
    new_env["HTTP_PROXY"] = db_http_proxy
    new_env["HTTPS_PROXY"] = db_https_proxy
    new_env["no_proxy"] = db_no_proxy
    new_env["NO_PROXY"] = db_no_proxy
    LOG.debug("Patching process env with proxy settings")
    os.environ.update(new_env)


def should_bypass(no_proxies: Iterable[str], endpoint: str) -> bool:
    """Check if the endpoint should be bypassed.

    This function will check if the endpoint is in the no_proxy
    list. If no_proxy is empty, it will return False.
    """
    if not no_proxies:
        return False

    host = endpoint.rsplit(":", 1)[0]
    host_ip = None

    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        # Not an IP address, continue
        pass
    for no_proxy in no_proxies:
        if (
            endpoint == no_proxy
            or (no_proxy.startswith("*") and endpoint.endswith(no_proxy[1:]))
            or (no_proxy.startswith(".") and endpoint.endswith(no_proxy))
        ):
            return True
        if host_ip:
            try:
                no_proxy_net = ipaddress.ip_network(no_proxy, strict=False)
                if host_ip in no_proxy_net:
                    return True
            except ValueError:
                # Not an IP address, continue
                pass
    return False
