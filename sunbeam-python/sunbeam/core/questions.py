# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import sys
import typing
from pathlib import Path
from typing import Callable

import yaml
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.text import Text

from sunbeam.clusterd.client import Client
from sunbeam.clusterd.service import ConfigItemNotFoundException
from sunbeam.core.common import SunbeamException

LOG = logging.getLogger(__name__)
PASSWORD_MASK = "*" * 8


class PasswordPrompt(Prompt):
    """Prompt that asks for a password."""

    def render_default(self, default: str) -> Text:  # type: ignore [override]
        """Turn the supplied default in to a Text instance.

        Args:
            default (DefaultType): Default value.

        Returns:
            Text: Text containing rendering of masked password value.
        """
        return Text(f"({default[:2]}{PASSWORD_MASK})", "prompt.default")


# workaround until https://github.com/Textualize/rich/issues/2994 is fixed
class StreamWrapper:
    def __init__(self, read_stream, write_stream):
        self.read_stream = read_stream
        self.write_stream = write_stream

    def readline(self):
        """Wrap readline, return empty string instead of None."""
        value = self.read_stream.readline()
        if value == "\n":
            return ""
        return value

    def flush(self):
        """Wrap flush, do nothing."""
        self.read_stream.flush()

    def write(self, s: str):
        """Write to the stream."""
        self.write_stream.write(s)


STREAM = StreamWrapper(sys.stdin, sys.stdout)


def get_stdin_reopen_tty() -> str:
    """Get stdin content and reopen tty if needed.

    This function reads a single line from stdin and reopens the tty
    if stdin is not a tty.
    """
    stdin_input = sys.stdin.readline().strip()

    if not sys.stdin.isatty():
        try:
            sys.stdin.close()
            sys.stdin = open("/dev/tty", "r")
        except OSError as e:
            LOG.debug("Failed to reopen stdin to /dev/tty: %s", e)
            raise SunbeamException("Failed to open terminal for input") from e
        # note(gboutry): Reassign stream wrapper read_stream
        # to the new stdin.
        STREAM.read_stream = sys.stdin
        LOG.debug("Reopened stdin to /dev/tty")
    return stdin_input


T = typing.TypeVar("T")


class Question(typing.Generic[T]):
    """A Question to be resolved."""

    question: str
    answer: T | None
    preseed: T | None
    previous_answer: T | None
    default_value: T | None
    choices: list[T] | None

    password: bool
    accept_defaults: bool
    default_function: Callable[[], T] | None
    validation_function: Callable[[T], None] | None
    description: str | None
    show_hint: bool
    console: Console | None

    def __init__(
        self,
        question: str,
        default_function: Callable[[], T] | None = None,
        default_value: T | None = None,
        choices: list | None = None,
        password: bool = False,
        validation_function: Callable[[T], None] | None = None,
        description: str | None = None,
    ):
        """Setup question.

        :param question: The string to display to the user
        :param default_function: A function to use to generate a default value,
                                 for example a password generating function.
        :param default_value: A value to use as the default for the question
        :param choices: A list of choices for the user to choose from
        :param console: the console to prompt on
        :param password: whether answer to question is a password
        :param validation_function: A function to use to validate the answer,
                                    must raise ValueError when value is
                                    invalid.
        :param description: A description of the question, displayed when
                            asking.
        """
        self.preseed = None
        self.console = None
        self.previous_answer = None
        self.answer = None
        self.question = question
        self.default_function = default_function
        self.default_value = default_value
        self.choices = choices
        self.accept_defaults = False
        self.password = password
        self.validation_function = validation_function
        self.description = description
        self.show_hint = False

    @property
    def question_function(self) -> Callable[..., T]:
        """Allow subclasses to define the question function."""
        raise NotImplementedError

    def calculate_default(self, new_default: T | None = None) -> T | None:
        """Find the value to should be presented to the user as the default.

        This is order of preference:
           1) The users previous answer
           2) A default supplied when the question was asked
           3) The result of the default_function
           4) The default_value for the question.

        :param new_default: The new default for the question.
        """
        default = None
        if self.previous_answer is not None:
            default = self.previous_answer
        elif new_default is not None:
            default = new_default
        elif self.default_function:
            default = self.default_function()
            if not self.password:
                LOG.debug("Value from default function {}".format(default))
        elif self.default_value is not None:
            default = self.default_value
        return default

    def ask(
        self,
        new_default: T | None = None,
        new_choices: list[T] | None = None,
    ) -> T | None:
        """Ask a question if needed.

        If a preseed has been supplied for this question then do not ask the
        user.

        :param new_default: The new default for the question. The idea here is
                            that previous answers may impact the value of a
                            sensible default so the original default can be
                            overriden at the point of prompting the user.
        :param new_choices: The new choices for the question.
        """
        if self.preseed is not None:
            self.answer = self.preseed
        else:
            default = self.calculate_default(new_default=new_default)
            if self.accept_defaults:
                self.answer = default
            else:
                if self.console and self.description and self.show_hint:
                    self.console.print(self.description, style="bright_black")
                self.answer = self.question_function(
                    self.question,
                    default=default,
                    console=self.console,
                    choices=new_choices or self.choices,
                    password=self.password,
                    stream=STREAM,
                )
        if self.validation_function is not None and self.answer is not None:
            try:
                self.validation_function(self.answer)  # type: ignore
            except ValueError as e:
                message = f"Invalid value for {self.question!r}: {e}"
                if self.preseed is not None:
                    LOG.error(message)
                    raise
                LOG.warning(message)
                self.ask(new_default=new_default)

        return self.answer


class PromptQuestion(Question[T]):
    """Ask the user a question."""

    @property
    def question_function(self):
        """Use default prompt function."""
        return Prompt.ask


class PasswordPromptQuestion(Question[T]):
    """Ask the user for a password."""

    @property
    def question_function(self):
        """Use password prompt function."""
        return PasswordPrompt.ask


class ConfirmQuestion(Question[T]):
    """Ask the user a simple yes / no question."""

    @property
    def question_function(self):
        """Use confirm prompt function."""
        return Confirm.ask


class QuestionBank:
    """A bank of questions.

    For example:

        class UserQuestions(QuestionBank):

            questions = {
                "username": PromptQuestion(
                    "Username to use for access to OpenStack",
                    default_value="demo"
                ),
                "password": PromptQuestion(
                    "Password to use for access to OpenStack",
                    default_function=generate_password,
                ),
                "cidr": PromptQuestion(
                    "Network range to use for project network",
                    default_value="192.168.0.0/24"
                ),
                "security_group_rules": ConfirmQuestion(
                    "Setup security group rules for SSH and ICMP ingress",
                    default_value=True
                ),
            }

        user_questions = UserQuestions(
            console=console,
            preseed=preseed.get("user"),
            previous_answers=self.variables.get("user"),
        )
        username = user_questions.username.ask()
        password = user_questions.password.ask()
    """

    def __init__(
        self,
        questions: typing.Mapping[str, Question],
        console: Console | None = None,
        preseed: dict | None = None,
        previous_answers: dict | None = None,
        accept_defaults: bool = False,
        show_hint: bool = False,
    ):
        """Apply preseed and previous answers to questions in bank.

        :param questions: dictionary of questions
        :param console: the console to prompt on
        :param preseed: dict of answers to questions.
        :param previous_answers: Previous answers to the questions in the
                                 bank.
        """
        self.questions = questions
        self.preseed = preseed or {}
        self.previous_answers = previous_answers or {}
        for key in self.questions.keys():
            self.questions[key].console = console
            self.questions[key].accept_defaults = accept_defaults
            self.questions[key].show_hint = show_hint
        for key, value in self.preseed.items():
            if self.questions.get(key) is not None:
                self.questions[key].preseed = value
        for key, value in self.previous_answers.items():
            if self.previous_answers.get(key) is not None:
                if self.questions.get(key) is not None:
                    self.questions[key].previous_answer = value

    def __getattr__(self, attr):
        """Return a question from the bank."""
        return self.questions[attr]


def read_preseed(preseed_file: Path) -> dict:
    """Read the preseed file."""
    with preseed_file.open("r") as f:
        preseed_data = yaml.safe_load(f)
    return preseed_data


def load_answers(client: Client, key: str) -> dict:
    """Read answers from database."""
    variables = {}
    try:
        variables = json.loads(client.cluster.get_config(key))
    except ConfigItemNotFoundException as e:
        LOG.debug(f"{key}: " + str(e))
    return variables


def write_answers(client: Client, key: str, answers):
    """Write answers to database."""
    client.cluster.update_config(key, json.dumps(answers))


def show_questions(
    question_bank,
    section=None,
    subsection=None,
    section_description=None,
    comment_out=False,
    initial_indent=4,
) -> list:
    """Return preseed questions as list."""
    lines = []
    space = " "
    indent = ""
    outer_indent = space * initial_indent
    if comment_out:
        comment = "# "
    else:
        comment = ""
    if section:
        if section_description:
            lines.append(
                f"{outer_indent}{comment}{indent}# {section_description}")
        lines.append(f"{outer_indent}{comment}{indent}{section}:")
        indent = space * 2
    # TODO(hemanth): To handle multi level subsections,
    # TODO: currently only one level is
    # considered
    if subsection:
        lines.append(f"{outer_indent}{comment}{indent}{subsection}:")
        indent = space * 4
    # TODO(hemanth): Repeat Questions bank for multiple subsections
    # TODO: of same type
    # Example: To generate preseed with microceph_config for multiple nodes
    # if values are available in cluster db.
    for key, question in question_bank.questions.items():
        default = question.calculate_default()
        if default is None:
            default = ""
        lines.append(f"{outer_indent}{comment}{indent}# {question.question}")
        if description := question.description:
            for line in description.splitlines():
                lines.append(f"{outer_indent}{comment}{indent}# {line}")
        lines.append(f"{outer_indent}{comment}{indent}{key}: {default}")

    return lines
