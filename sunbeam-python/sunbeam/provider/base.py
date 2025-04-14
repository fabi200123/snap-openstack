# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import abc
from typing import Tuple, Type

import click
from rich.console import Console

from sunbeam.core.deployment import Deployment

console = Console()


class ProviderBase(abc.ABC):
    @abc.abstractmethod
    def register_add_cli(
        self,
        add: click.Group,
    ) -> None:
        """Register common commands to CLI.

        Always call to register commands that must be present.
        """
        pass

    @abc.abstractmethod
    def register_cli(
        self,
        init: click.Group,
        configure: click.Group,
        deployment: click.Group,
    ) -> None:
        """Register provider specific commands to CLI.

        Only called when the provider is enabled.
        """
        pass

    def deployment_type(self) -> Tuple[str, Type[Deployment]]:
        """Return a deployment type for the provider."""
        raise NotImplementedError
