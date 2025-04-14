# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import logging

import click
from rich.console import Console
from snaphelpers import Snap

from sunbeam.core.common import BaseStep, run_plan
from sunbeam.core.deployment import Deployment
from sunbeam.steps.juju import (
    RegisterRemoteJujuUserStep,
    SwitchToController,
    UnregisterJujuController,
)
from sunbeam.utils import click_option_show_hints

LOG = logging.getLogger(__name__)
console = Console()


@click.command()
@click.option(
    "-f",
    "--force",
    is_flag=True,
    help="Force replacement if controller already exists with the same name",
)
@click.argument("name", type=str)
@click.argument("token", type=str)
@click_option_show_hints
@click.pass_context
def register_controller(
    ctx: click.Context, name: str, token: str, force: bool, show_hints: bool
) -> None:
    """Register existing Juju controller."""
    deployment: Deployment = ctx.obj
    data_location = Snap().paths.user_data

    plan: list[BaseStep] = []
    plan.append(RegisterRemoteJujuUserStep(token, name, data_location, replace=force))
    if deployment.juju_controller:
        plan.append(SwitchToController(deployment.juju_controller.name))

    run_plan(plan, console, show_hints)
    console.print(f"Controller {name} registered")


@click.command()
@click.argument("name", type=str)
@click_option_show_hints
@click.pass_context
def unregister_controller(ctx: click.Context, name: str, show_hints: bool) -> None:
    """Unregister external Juju controller."""
    data_location = Snap().paths.user_data
    plan = [UnregisterJujuController(name, data_location)]
    run_plan(plan, console, show_hints)
    console.print(f"Controller {name} unregistered")
