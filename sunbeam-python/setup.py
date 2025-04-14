# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import setuptools

setuptools.setup(
    setup_requires=["pbr>=2.0.0"],
    pbr=True,
    package_data={
        "sunbeam": [
            "features/features.yaml",
            "features/*/etc/*/*.tf",
            "features/*/etc/*/modules/*/*.tf",
        ]
    },
)
