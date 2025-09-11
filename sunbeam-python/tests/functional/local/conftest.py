# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import pytest

from . import utils


def pytest_addoption(parser):
    parser.addoption(
        "--manifest-path",
        action="store",
        help=(
            "Sunbeam manifest used for testing purposes. "
            "Modified versions of it will be passed during bootstrap "
            "and other Sunbeam operations."
        ),
    )
    parser.addoption(
        "--openstack-snap-channel",
        action="store",
        help="The snap channel used when installing the Openstack snap.",
        default="2024.1/edge",
    )
    parser.addoption(
        "--sriov-interface-name",
        action="store",
        help="The name of a network interface used for SR-IOV testing.",
    )
    parser.addoption(
        "--physnet",
        action="store",
        help="The default Neutron physical network used during the tests.",
        default="physnet1",
    )


@pytest.fixture(scope="session")
def manifest_path(request) -> str:
    return request.config.getoption("manifest_path")


@pytest.fixture(scope="session")
def openstack_snap_channel(request) -> str:
    return request.config.getoption("openstack_snap_channel")


@pytest.fixture(scope="session")
def sriov_interface_name(request) -> str:
    return request.config.getoption("sriov_interface_name")


@pytest.fixture(scope="session")
def physnet(request) -> str:
    return request.config.getoption("physnet")


@pytest.fixture(scope="session", autouse=True)
def ensure_local_cluster_bootstrapped(manifest_path, openstack_snap_channel):
    utils.ensure_local_cluster_bootstrapped(manifest_path, openstack_snap_channel)
