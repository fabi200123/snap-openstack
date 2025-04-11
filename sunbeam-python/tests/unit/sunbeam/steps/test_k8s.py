# Copyright (c) 2024 Canonical Ltd. Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from lightkube import ApiError

from sunbeam.clusterd.service import ConfigItemNotFoundException
from sunbeam.core.common import ResultType
from sunbeam.core.juju import (
    ActionFailedException,
    ApplicationNotFoundException,
    LeaderNotFoundException,
)
from sunbeam.steps.k8s import (
    CREDENTIAL_SUFFIX,
    K8S_CLOUD_SUFFIX,
    AddK8SCloudStep,
    AddK8SCredentialStep,
    EnsureL2AdvertisementByHostStep,
    StoreK8SKubeConfigStep,
)


@pytest.fixture(autouse=True)
def mock_run_sync(mocker):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()

    def run_sync(coro):
        return loop.run_until_complete(coro)

    mocker.patch("sunbeam.steps.k8s.run_sync", run_sync)
    yield
    loop.close()


class TestAddK8SCloudStep(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)

    def setUp(self):
        self.deployment = Mock()
        self.cloud_name = f"{self.deployment.name}{K8S_CLOUD_SUFFIX}"
        self.deployment.get_client().cluster.get_config.return_value = "{}"
        self.jhelper = AsyncMock()

    def test_is_skip(self):
        clouds = {}
        self.jhelper.get_clouds.return_value = clouds

        step = AddK8SCloudStep(self.deployment, self.jhelper)
        result = step.is_skip()

        assert result.result_type == ResultType.COMPLETED

    def test_is_skip_cloud_already_deployed(self):
        clouds = {f"cloud-{self.cloud_name}": {"endpoint": "10.0.10.1"}}
        self.jhelper.get_clouds.return_value = clouds

        step = AddK8SCloudStep(self.deployment, self.jhelper)
        result = step.is_skip()

        assert result.result_type == ResultType.SKIPPED

    def test_run(self):
        with patch("sunbeam.steps.k8s.read_config", Mock(return_value={})):
            step = AddK8SCloudStep(self.deployment, self.jhelper)
            result = step.run()

        self.jhelper.add_k8s_cloud.assert_called_with(
            self.cloud_name,
            f"{self.cloud_name}{CREDENTIAL_SUFFIX}",
            {},
        )
        assert result.result_type == ResultType.COMPLETED


class TestAddK8SCredentialStep(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)

    def setUp(self):
        self.deployment = Mock()
        self.deployment.name = "mydeployment"
        self.cloud_name = f"{self.deployment.name}{K8S_CLOUD_SUFFIX}"
        self.credential_name = f"{self.cloud_name}{CREDENTIAL_SUFFIX}"
        self.deployment.get_client().cluster.get_config.return_value = "{}"
        self.jhelper = AsyncMock()

    def test_is_skip(self):
        credentials = {}
        self.jhelper.get_credentials.return_value = credentials

        step = AddK8SCredentialStep(self.deployment, self.jhelper)
        with patch.object(step, "get_credentials", return_value=credentials):
            result = step.is_skip()

        assert result.result_type == ResultType.COMPLETED

    def test_is_skip_credential_exists(self):
        credentials = {"controller-credentials": {self.credential_name: {}}}
        self.jhelper.get_credentials.return_value = credentials

        step = AddK8SCredentialStep(self.deployment, self.jhelper)
        with patch.object(step, "get_credentials", return_value=credentials):
            result = step.is_skip()

        assert result.result_type == ResultType.SKIPPED

    def test_run(self):
        with patch("sunbeam.steps.k8s.read_config", Mock(return_value={})):
            step = AddK8SCredentialStep(self.deployment, self.jhelper)
            result = step.run()

        self.jhelper.add_k8s_credential.assert_called_with(
            self.cloud_name,
            self.credential_name,
            {},
        )
        assert result.result_type == ResultType.COMPLETED


class TestStoreK8SKubeConfigStep(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)

    def setUp(self):
        self.client = Mock(cluster=Mock(get_config=Mock(return_value="{}")))
        self.jhelper = AsyncMock()
        self.deployment = Mock()
        mock_machine = MagicMock()
        mock_machine.addresses = [
            {"value": "127.0.0.1:16443", "space-name": "management"}
        ]
        self.jhelper.get_machines.return_value = {"0": mock_machine}
        self.deployment.get_space.return_value = "management"

    def test_is_skip(self):
        step = StoreK8SKubeConfigStep(
            self.deployment, self.client, self.jhelper, "test-model"
        )
        result = step.is_skip()

        assert result.result_type == ResultType.SKIPPED

    def test_is_skip_config_missing(self):
        with patch(
            "sunbeam.steps.k8s.read_config",
            Mock(side_effect=ConfigItemNotFoundException),
        ):
            step = StoreK8SKubeConfigStep(
                self.deployment, self.client, self.jhelper, "test-model"
            )
            result = step.is_skip()

        assert result.result_type == ResultType.COMPLETED

    def test_run(self):
        kubeconfig_content = """apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: fakecert
    server: https://127.0.0.1:16443
  name: k8s-cluster
contexts:
- context:
    cluster: k8s-cluster
    user: admin
  name: k8s
current-context: k8s
kind: Config
preferences: {}
users:
- name: admin
  user:
    token: faketoken"""

        action_result = {
            "kubeconfig": kubeconfig_content,
        }
        self.jhelper.run_action.return_value = action_result
        self.jhelper.get_leader_unit_machine.return_value = "0"
        self.jhelper.get_machine_interfaces.return_value = {
            "enp0s8": {
                "ip-addresses": ["127.0.0.1"],
                "space": "management",
            }
        }

        step = StoreK8SKubeConfigStep(
            self.deployment, self.client, self.jhelper, "test-model"
        )
        result = step.run()

        self.jhelper.get_leader_unit.assert_called_once()
        self.jhelper.run_action.assert_called_once()
        assert result.result_type == ResultType.COMPLETED

    def test_run_application_not_found(self):
        self.jhelper.get_leader_unit.side_effect = ApplicationNotFoundException(
            "Application missing..."
        )

        step = StoreK8SKubeConfigStep(
            self.deployment, self.client, self.jhelper, "test-model"
        )
        result = step.run()

        self.jhelper.get_leader_unit.assert_called_once()
        assert result.result_type == ResultType.FAILED
        assert result.message == "Application missing..."

    def test_run_leader_not_found(self):
        self.jhelper.get_leader_unit.side_effect = LeaderNotFoundException(
            "Leader missing..."
        )

        step = StoreK8SKubeConfigStep(
            self.deployment, self.client, self.jhelper, "test-model"
        )
        result = step.run()

        self.jhelper.get_leader_unit.assert_called_once()
        assert result.result_type == ResultType.FAILED
        assert result.message == "Leader missing..."

    def test_run_action_failed(self):
        self.jhelper.run_action.side_effect = ActionFailedException("Action failed...")
        self.jhelper.get_leader_unit.return_value = "k8s/0"
        self.jhelper.get_leader_unit_machine.return_value = "0"
        self.jhelper.get_machine_interfaces.return_value = {
            "enp0s8": {
                "ip-addresses": ["127.0.0.1"],
                "space": "management",
            }
        }
        step = StoreK8SKubeConfigStep(
            self.deployment, self.client, self.jhelper, "test-model"
        )
        result = step.run()

        self.jhelper.get_leader_unit.assert_called_once()
        self.jhelper.run_action.assert_called_once()
        assert result.result_type == ResultType.FAILED
        assert result.message == "Action failed..."


class TestEnsureL2AdvertisementByHostStep(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)

    def setUp(self):
        self.deployment = Mock()
        self.control_nodes = [
            {"name": "node1", "machineid": "1"},
            {"name": "node2", "machineid": "2"},
        ]
        self.client = Mock(
            cluster=Mock(
                list_nodes_by_role=Mock(return_value=self.control_nodes),
                get_config=Mock(return_value="{}"),
            )
        )
        self.jhelper = AsyncMock()
        self.model = "test-model"
        self.network = Mock()
        self.pool = "test-pool"
        self.step = EnsureL2AdvertisementByHostStep(
            self.deployment,
            self.client,
            self.jhelper,
            self.model,
            self.network,
            self.pool,
        )
        self.step.kube = Mock()
        self.step.kubeconfig = Mock()

        self.kubeconfig_mocker = patch(
            "sunbeam.steps.k8s.l_kubeconfig.KubeConfig",
            Mock(from_dict=Mock(return_value=self.step.kubeconfig)),
        )
        self.kubeconfig_mocker.start()
        self.kube_mocker = patch(
            "sunbeam.steps.k8s.l_client.Client",
            Mock(return_value=Mock(return_value=self.step.kube)),
        )
        self.kube_mocker.start()

    def test_is_skip_no_outdated_or_deleted(self):
        self.step._get_outdated_l2_advertisement = Mock(return_value=([], []))
        result = self.step.is_skip()
        assert result.result_type == ResultType.SKIPPED

    def test_is_skip_with_outdated(self):
        self.step._get_outdated_l2_advertisement = Mock(return_value=(["node1"], []))
        result = self.step.is_skip()
        assert result.result_type == ResultType.COMPLETED
        assert len(self.step.to_update) == 1

    def test_is_skip_with_deleted(self):
        self.step._get_outdated_l2_advertisement = Mock(return_value=([], ["node2"]))
        result = self.step.is_skip()
        assert result.result_type == ResultType.COMPLETED
        assert len(self.step.to_delete) == 1

    def test_run_update_and_delete(self):
        self.step.to_update = [{"name": "node1", "machineid": "1"}]
        self.step.to_delete = [{"name": "node2", "machineid": "2"}]
        self.step._get_interface = Mock(return_value="eth0")
        self.step.kube.apply = Mock()
        self.step.kube.delete = Mock()

        result = self.step.run(None)

        self.step.kube.apply.assert_called_once()
        self.step.kube.delete.assert_called_once()
        assert result.result_type == ResultType.COMPLETED

    def test_run_update_failure(self):
        self.step.to_update = [{"name": "node1", "machineid": "1"}]
        self.step.to_delete = []
        self.step._get_interface = Mock(return_value="eth0")
        api_error = ApiError.__new__(ApiError)
        api_error.status = Mock(code=500)
        self.step.kube.apply = Mock(side_effect=api_error)

        result = self.step.run(None)

        self.step.kube.apply.assert_called_once()
        assert result.result_type == ResultType.FAILED

    def test_run_delete_failure(self):
        self.step.to_update = []
        self.step.to_delete = [{"name": "node2", "machineid": "2"}]
        api_error = ApiError.__new__(ApiError)
        api_error.status = Mock(code=500)
        self.step.kube.delete = Mock(side_effect=api_error)

        result = self.step.run(None)

        self.step.kube.delete.assert_called_once()
        assert result.result_type == ResultType.COMPLETED

    def test_get_interface_cached(self):
        self.step._ifnames = {"node1": "eth0"}
        result = self.step._get_interface({"name": "node1"}, self.network)
        assert result == "eth0"

    def test_get_interface_found(self):
        self.jhelper.get_machine_interfaces.return_value = {
            "eth0": {"space": "management"},
            "eth1": {"space": "other-space"},
        }
        self.deployment.get_space.return_value = "management"
        result = self.step._get_interface(
            {"name": "node1", "machineid": "1"}, self.network
        )
        assert result == "eth0"
        assert self.step._ifnames["node1"] == "eth0"

    def test_get_interface_not_found(self):
        self.jhelper.get_machine_interfaces.return_value = {
            "eth0": {"space": "other-space"},
            "eth1": {"space": "another-space"},
        }
        self.deployment.get_space.return_value = "management"
        with self.assertRaises(EnsureL2AdvertisementByHostStep._L2AdvertisementError):
            self.step._get_interface({"name": "node1", "machineid": "1"}, self.network)


def _to_kube_object(metadata: dict, spec: dict | None) -> object:
    """Convert a dictionary to a mock object."""
    obj = Mock()
    obj.metadata = Mock(**metadata)
    obj.spec = spec
    return obj


_l2_outdated_testcases = {
    "1-node-no-l2": ([{"name": "node1", "interface": "eth0"}], [], ["node1"], []),
    "1-node-matching-l2": (
        [{"name": "node1", "interface": "eth0"}],
        [
            _to_kube_object(
                metadata={"labels": {"sunbeam/hostname": "node1"}},
                spec={"ipAddressPools": ["test-pool"], "interfaces": ["eth0"]},
            )
        ],
        [],
        [],
    ),
    "1-node-wrong-pool-l2": (
        [{"name": "node1", "interface": "eth0"}],
        [
            _to_kube_object(
                metadata={"labels": {"sunbeam/hostname": "node1"}},
                spec={"ipAddressPools": ["my-pool"], "interfaces": ["eth0"]},
            )
        ],
        ["node1"],
        [],
    ),
    "1-node-wrong-interface-l2": (
        [{"name": "node1", "interface": "eth0"}],
        [
            _to_kube_object(
                metadata={"labels": {"sunbeam/hostname": "node1"}},
                spec={"ipAddressPools": ["test-pool"], "interfaces": ["eth1"]},
            )
        ],
        ["node1"],
        [],
    ),
    "0-node-l2-advertisement": (
        [],
        [
            _to_kube_object(
                metadata={"labels": {"sunbeam/hostname": "node1"}},
                spec={"ipAddressPools": ["test-pool"], "interfaces": ["eth0"]},
            )
        ],
        [],
        ["node1"],
    ),
    "2-nodes-1-missing-l2-1-outdated-l2-1-l2-to-delete": (
        [
            {"name": "node2", "interface": "2"},
            {"name": "node3", "interface": "3"},
        ],
        [
            _to_kube_object(
                metadata={"labels": {"sunbeam/hostname": "node1"}},
                spec={"ipAddressPools": ["test-pool"], "interfaces": ["eth0"]},
            ),
            _to_kube_object(
                metadata={"labels": {"sunbeam/hostname": "node2"}},
                spec={"ipAddressPools": ["my-pool"], "interfaces": ["eth1"]},
            ),
        ],
        ["node2", "node3"],
        ["node1"],
    ),
    "missing-metadata": (
        [{"name": "node1", "interface": "eth0"}],
        [Mock(metadata=None)],
        ["node1"],
        [],
    ),
    "missing-labels": (
        [{"name": "node1", "interface": "eth0"}],
        [
            _to_kube_object(
                metadata={"labels": None},
                spec={"ipAddressPools": ["test-pool"], "interfaces": ["eth0"]},
            )
        ],
        ["node1"],
        [],
    ),
    "missing-hostname-in-labels": (
        [{"name": "node1", "interface": "eth0"}],
        [
            _to_kube_object(
                metadata={"labels": {}},
                spec={"ipAddressPools": ["test-pool"], "interfaces": ["eth0"]},
            )
        ],
        ["node1"],
        [],
    ),
    "missing-spec": (
        [{"name": "node1", "interface": "eth0"}],
        [
            _to_kube_object(
                metadata={"labels": {"sunbeam/hostname": "node1"}},
                spec=None,
            )
        ],
        ["node1"],
        [],
    ),
}


@pytest.mark.parametrize(
    "nodes,list,outdated,deleted",
    _l2_outdated_testcases.values(),
    ids=_l2_outdated_testcases.keys(),
)
def test_get_outdated_l2_advertisement(
    nodes: list[dict], list: list[object], outdated: list[str], deleted: list[str]
):
    kube = Mock(list=Mock(return_value=list))
    step = EnsureL2AdvertisementByHostStep(
        Mock(),
        Mock(),
        Mock(),
        "test-model",
        Mock(),
        "test-pool",
    )

    def _get_interface(node, network):
        for node_it in nodes:
            if node_it["name"] == node["name"]:
                return node_it["interface"]
        raise EnsureL2AdvertisementByHostStep._L2AdvertisementError()

    step._get_interface = Mock(side_effect=_get_interface)

    outdated_res, deleted_res = step._get_outdated_l2_advertisement(nodes, kube)

    assert outdated_res == outdated
    assert deleted_res == deleted
