# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import pbr.version  # type: ignore [import-untyped]

__all__ = ["__version__"]
version_info = pbr.version.VersionInfo("sunbeam")
try:
    __version__ = version_info.version_string()
except AttributeError:
    __version__ = None
