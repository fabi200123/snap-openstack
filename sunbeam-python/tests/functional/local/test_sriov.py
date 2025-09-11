# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import logging

import pytest

from . import snap, utils

# The number of VFs to create if there aren't any existing ones.
DEFAULT_NUM_VFS = 4


def test_sriov(tmp_path, manifest_path, physnet, sriov_interface_name: str):
    if not sriov_interface_name:
        pytest.skip("No SR-IOV interface specified, skipping SR-IOV tests.")

    pci_address = utils.get_iface_pci_address(sriov_interface_name)
    logging.info("Detected SR-IOV interface PCI address: %s", pci_address)

    if not utils.is_sriov_capable(pci_address):
        raise Exception(
            "The specified interface name does not support SR-IOV: %s"
            % sriov_interface_name
        )

    num_vfs = utils.get_sriov_numvfs(pci_address)
    if num_vfs <= 0:
        num_vfs = DEFAULT_NUM_VFS
        logging.info("No SR-IOV VFs defined, creating %s", num_vfs)
        utils.set_sriov_numvfs(pci_address, num_vfs)

    has_hw_offload = utils.is_hw_offload_available(sriov_interface_name)
    logging.info("Hardware offloading available: %s", has_hw_offload)

    # The device specs are expected to contain a physnet unless overlay
    # networks are used (requires hardware offloading).
    if has_hw_offload:
        physnet = None
    manifest_updates = {
        "core": {
            "config": {
                "pci": {
                    "device_specs": [
                        {
                            "address": pci_address,
                            "physical_network": physnet,
                        },
                    ]
                }
            }
        }
    }
    sriov_manifest_path = tmp_path / "sriov-manifest.yaml"
    utils.apply_manifest(
        destination_manifest_path=str(sriov_manifest_path),
        manifest_updates=manifest_updates,
        base_manifest_path=manifest_path,
    )

    logging.info("Applying SR-IOV configuration.")
    utils.sunbeam_command(
        f"-v configure sriov -m {sriov_manifest_path} --accept-defaults"
    )

    snap_cache = snap.SnapCache()
    openstack_hypervisor_snap = snap_cache["openstack-hypervisor"]

    assert "neutron-sriov-nic-agent" in openstack_hypervisor_snap.services
    sriov_agent_service = openstack_hypervisor_snap.services["neutron-sriov-nic-agent"]
    # If hardware offloading is available, the VFs are handled by the
    # OVN mechanism driver. If not, the SR-IOV mechanism driver will
    # bind the ports, leveraging the SR-IOV nic agent.
    sriov_agent_expected = not has_hw_offload
    assert sriov_agent_service["enabled"] == sriov_agent_expected

    _ensure_vfs_whitelisted(pci_address, num_vfs)


def _get_nova_conf_device_specs() -> list[dict]:
    nova_conf_raw = utils.privileged_file_read(
        "/var/snap/openstack-hypervisor/common/etc/nova/nova.conf"
    )
    device_specs = []
    for line in nova_conf_raw.split("\n"):
        if line.startswith("device_spec = "):
            spec_json = line.replace("device_spec = ", "")
            spec = json.loads(spec_json)
            device_specs.append(spec)
    return device_specs


def _ensure_vfs_whitelisted(pf_address, num_vfs):
    device_specs = _get_nova_conf_device_specs()

    # The Nova PCI whitelist may contain wildcards, however
    # Sunbeam will pass the exact address of whitelisted VFs.
    found_vfs = []
    for spec in device_specs:
        spec_address = spec.get("address")
        if not spec_address:
            continue
        parent_pf_address = utils.get_physfn_address(spec_address)
        if parent_pf_address != pf_address:
            continue
        # Found a matching vf.
        found_vfs.append(spec_address)

    assert len(found_vfs) == num_vfs
