# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import logging
import subprocess

from . import utils


def test_dpdk(tmp_path, manifest_path):
    manifest_updates = {
        "core": {
            "config": {
                "dpdk": {
                    "enabled": "true",
                    "datapath_cores": 1,
                    "control_plane_cores": 1,
                    "memory": 1024,
                    "driver": "vfio-pci",
                    "ports": {},
                }
            }
        }
    }
    dpdk_manifest_path = tmp_path / "dpdk-manifest.yaml"
    utils.apply_manifest(
        destination_manifest_path=str(dpdk_manifest_path),
        manifest_updates=manifest_updates,
        base_manifest_path=manifest_path,
    )

    logging.info("Applying DPDK configuration.")
    utils.sunbeam_command(
        f"-v configure dpdk -m {dpdk_manifest_path} --accept-defaults"
    )

    ovs_config = utils.ovs_vsctl_list_table("Open_vSwitch", ".", ["other-config"])
    assert ovs_config["other_config"]["dpdk-init"] == "try"

    dpdk_memory = ovs_config["other_config"]["dpdk-socket-mem"]
    dpdk_lcore_mask = ovs_config["other_config"]["dpdk-lcore-mask"]
    pmd_cpu_mask = ovs_config["other_config"]["dpdk-lcore-mask"]

    assert 1 == len(utils.bitmask_to_core_list(int(dpdk_lcore_mask, 16)))
    assert 1 == len(utils.bitmask_to_core_list(int(pmd_cpu_mask, 16)))

    dpdk_memory_numa = dpdk_memory.split(",")
    assert dpdk_memory_numa[0] == "1024"
    if len(dpdk_memory_numa) > 0:
        for mem_numa in dpdk_memory_numa[1:]:
            assert mem_numa == "0"

    dpdk_initialized = subprocess.check_output(
        [
            "sudo",
            "openstack-hypervisor.ovs-vsctl",
            "get",
            "Open_vSwitch",
            ".",
            "dpdk_initialized",
        ],
        text=True,
    )
    assert dpdk_initialized.strip() == "true"
