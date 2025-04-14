# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import types
from functools import cached_property
from importlib import import_module


class LazyImport(types.ModuleType):
    def __init__(self, name: str):
        self._name = name

    def __getattr__(self, item):
        """__getattr__ override."""
        return getattr(self._module, item)

    @cached_property
    def _module(self) -> types.ModuleType:
        return import_module(self._name)
