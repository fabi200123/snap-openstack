# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import logging
import typing
import re
from pathlib import Path

import click
import pydantic
import yaml
from packaging.version import Version
from rich.console import Console
from rich.status import Status
from rich.table import Table

from sunbeam.clusterd.client import Client
from sunbeam.clusterd.service import (
    ConfigItemNotFoundException,
)
from sunbeam.core import questions
from sunbeam.core.common import (
    FORMAT_TABLE,
    FORMAT_YAML,
    BaseStep,
    Result,
    ResultType,
    read_config,
    run_plan,
    str_presenter,
    SunbeamException,
)
from sunbeam.core.deployment import Deployment
from sunbeam.core.juju import (
    ActionFailedException,
    JujuHelper,
    LeaderNotFoundException,
    run_sync,
)
from sunbeam.core.manifest import (
    AddManifestStep,
    CharmManifest,
    FeatureConfig,
    SoftwareConfig,
)
from sunbeam.core.openstack import OPENSTACK_MODEL
from sunbeam.features.interface.utils import (
    encode_base64_as_string,
    get_subject_from_csr,
    is_certificate_valid,
    validate_ca_certificate,
    validate_ca_chain,
)
from sunbeam.features.interface.v1.openstack import (
    TerraformPlanLocation,
    WaitForApplicationsStep,
)
from sunbeam.features.tls.common import (
    INGRESS_CHANGE_APPLICATION_TIMEOUT,
    TlsFeature,
    TlsFeatureConfig,
    certificate_questions,
    get_outstanding_certificate_requests,
)
from sunbeam.utils import click_option_show_hints, pass_method_obj

CERTIFICATE_FEATURE_KEY = "TlsProvider"
CA_APP_NAME = "vault"
LOG = logging.getLogger(__name__)
console = Console()
ConfigType = typing.TypeVar("ConfigType", bound=FeatureConfig)


class _Certificate(pydantic.BaseModel):
    certificate: str


class VaultTlsFeatureConfig(TlsFeatureConfig):
    certificates: dict[str, _Certificate] = {}


class ConfigureVaultCAStep(BaseStep):
    """Configure CA certificates."""

    _CONFIG = "FeatureCACertificatesConfig"

    def __init__(
        self,
        client: Client,
        jhelper: JujuHelper,
        ca_cert: str,
        ca_chain: str,
        deployment_preseed: dict | None = None,
    ):
        super().__init__("Configure CA certs", "Configuring CA certificates")
        self.client = client
        self.jhelper = jhelper
        self.ca_cert = ca_cert
        self.ca_chain = ca_chain
        self.preseed = deployment_preseed or {}
        self.app = "manual-tls-certificates"
        self.model = OPENSTACK_MODEL
        self.process_certs: dict = {}

    def has_prompts(self) -> bool:
        """Returns true if the step has prompts that it can ask the user."""
        return True

    def prompt(
        self,
        console: Console | None = None,
        show_hint: bool = False,
    ) -> None:
        """Prompt the user for certificates.

        Prompts the user for required information for cert configuration.

        :param console: the console to prompt on
        :type console: rich.console.Console (Optional)
        """
        action_cmd = "get-outstanding-certificate-requests"
        # let exception propagate, since they are SunbeamException
        # they will be caught cleanly
        action_result = get_outstanding_certificate_requests(
            self.app, self.model, self.jhelper
        )

        LOG.debug(f"Result from action {action_cmd}: {action_result}")
        if action_result.get("return-code", 0) > 1:
            raise click.ClickException(
                "Unable to get outstanding certificate requests from CA"
            )

        certs_to_process = json.loads(action_result.get("result", "[]"))
        if not certs_to_process:
            LOG.debug("No outstanding certificates to process")
            return

        variables = questions.load_answers(self.client, self._CONFIG)
        variables.setdefault("certificates", {})
        self.preseed.setdefault("certificates", {})

        for record in certs_to_process:
            unit_name = record.get("unit_name")
            csr = record.get("csr")
            app = record.get("application_name")
            relation_id = record.get("relation_id")
            if not unit_name:
                unit_name = str(relation_id)

            # Each unit can have multiple CSRs
            subject = get_subject_from_csr(csr)
            if not subject:
                raise click.ClickException(
                    f"Not a valid CSR for unit {unit_name}")

            cert_questions = certificate_questions(unit_name, subject)
            certificates_bank = questions.QuestionBank(
                questions=cert_questions,
                console=console,
                preseed=self.preseed.get("certificates", {}).get(subject),
                previous_answers=variables.get("certificates", {}).get(subject),
                show_hint=show_hint,
            )
            cert = certificates_bank.certificate.ask()
            if not cert or not is_certificate_valid(cert):
                raise click.ClickException("Not a valid certificate")

            self.process_certs[subject] = {
                "app": app,
                "unit": unit_name,
                "relation_id": relation_id,
                "csr": csr,
                "certificate": cert,
            }
            variables["certificates"].setdefault(subject, {})
            variables["certificates"][subject]["certificate"] = cert

        questions.write_answers(self.client, self._CONFIG, variables)

    def is_skip(self, status: Status | None = None) -> Result:
        """Determines if the step should be skipped or not.

        :return: ResultType.SKIPPED if the Step should be skipped,
                ResultType.COMPLETED or ResultType.FAILED otherwise
        """
        return Result(ResultType.COMPLETED)

    def run(self, status: Status | None = None) -> Result:
        """Run configure steps."""
        action_cmd = "provide-certificate"
        try:
            unit = run_sync(self.jhelper.get_leader_unit(self.app, self.model))
        except LeaderNotFoundException as e:
            LOG.debug(f"Unable to get {self.app} leader")
            return Result(ResultType.FAILED, str(e))

        LOG.debug(f"Process certs: {self.process_certs}")
        for subject, request in self.process_certs.items():
            csr = request.get("csr")
            csr = encode_base64_as_string(csr)
            if not csr:
                return Result(ResultType.FAILED)
            new_ca_chain = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUg3ekNDQTllZ0F3SUJBZ0lDRUEwd0RRWUpLb1pJaHZjTkFRRUxCUUF3V0RFTE1Ba0dBMVVFQmhNQ1EwRXgKQ3pBSkJnTlZCQWdNQWtOQk1Rc3dDUVlEVlFRSERBSkRRVEVMTUFrR0ExVUVDZ3dDUTBFeEN6QUpCZ05WQkFzTQpBa05CTVJVd0V3WURWUVFEREF4dGVXUnZiV0ZwYmk1amIyMHdIaGNOTWpVd05qRTNNak0xTXpVNVdoY05NamN3Ck5qRTNNak0xTXpVNVdqQVhNUlV3RXdZRFZRUUREQXh0ZVdSdmJXRnBiaTVqYjIwd2dnRWlNQTBHQ1NxR1NJYjMKRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEWXE0MWtrb2xpL2hDTHRZWjdNMm41YXJ2Z1pVQ0YxOElpeFN0eQpKUEE3OU1MSE9NWUlEOXhVN2VUUVhqR0N0cHdmSEJ1UlU3WnBrczRCNmp5d2diMHhCZDRCUkJqQ2NIckRzM2Q5CmhieGJmVGVxVGUrcEJOeTFlTWNYQ2VRWnlQOEM0NnY3QTBkeDltaXpCVDM5YVNDNEJ4QTVJOVZNSXQ3OUxtN1EKSEU4SVd0RUVwTDBQM2ZSN2V1eStMTGdqNWdZWWxmN2liVFZWUHdVNGNRL3dCZUVGTHU1TGxKU0YwZnl1VzA2eQpVc3ROcElMeDB5ZVZkRDRNQXJIZURYb2hWNzVHb0djNmJJN1hVdXAzdTFlN0tjb3AyV1hHdHdaU1FaUXRrL2djCjNrK2FVRCt1MEIwS3Y3NWNlSnQ0dlpmdDIxT2JOd3dzek5wUlVTKzVSMTgvNVJFM0FnTUJBQUdqZ2dJQ01JSUIKL2pBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJTd0IyZUwrUTB1eTQ3cUNscEovS29abUZDaAp4akFmQmdOVkhTTUVHREFXZ0JSak9RWWIrek05V3dhdlN4d2hwako3Rnl1S3lUQUxCZ05WSFE4RUJBTUNBYVl3CkV3WURWUjBsQkF3d0NnWUlLd1lCQlFVSEF3RXdiQVlEVlIwZkJHVXdZekF5b0RDZ0xvWXNhSFIwY0RvdkwzQnIKYVM1emNHRnlhMnhwYm1kallTNWpiMjB2VTNCaGNtdHNhVzVuVW05dmRDNWpjbXd3TGFBcm9DbUdKMmgwZEhBNgpMeTl3YTJrdVltRmphM1Z3TG1OdmJTOVRjR0Z5YTJ4cGJtZFNiMjkwTG1OeWJEQkRCZ05WSFJFRVBEQTZnaHRUCmNHRnlhMnhwYm1jZ1NXNTBaWEp0YVdScFlYUmxJRU5CSURHQ0cxTndZWEpyYkdsdVp5QkRRU0JKYm5SbGNtMXAKWkdsaGRHVWdNVENCMVFZSUt3WUJCUVVIQVFFRWdjZ3dnY1V3T0FZSUt3WUJCUVVITUFLR0xHaDBkSEE2THk5dwphMmt1YzNCaGNtdHNhVzVuWTJFdVkyOXRMMU53WVhKcmJHbHVaMUp2YjNRdVkzSjBNRE1HQ0NzR0FRVUZCekFDCmhpZG9kSFJ3T2k4dmNHdHBMbUpoWTJ0MWNDNWpiMjB2VTNCaGNtdHNhVzVuVW05dmRDNWpjblF3TEFZSUt3WUIKQlFVSE1BR0dJR2gwZEhBNkx5OXdhMmt1YzNCaGNtdHNhVzVuWTJFdVkyOXRMMjlqYzNBdk1DWUdDQ3NHQVFVRgpCekFCaGhwb2RIUndPaTh2Y0d0cExtSmhZMnQxY0M1amIyMHZiMk56Y0RBTkJna3Foa2lHOXcwQkFRc0ZBQU9DCkJBRUFES3JTWHhuRHo3bW1HNUJvYkl2bkV2UC9Sck4wenRIOTNOWnVsV2tudHhldmFiV0pWNmJwZU1SQnQ3NDIKa01PdVphdzRrWDVGbWRMVlc0bHlpWTh1aWpGdTZEY1dmWEJleUFRVzA0cEs4UVVodWZCQi9jY0Q5Yks2bnUxcgovNzN1MmZTNWhpL0xqQ25OY1NtZFRKWWdSbHA3RDFObnJmRmxvM2t2UWoybXF2cGZuaUhZaHVxTWF2cVFJZm5QCkwzVkM2akxMQ2xIaUpXNHA0Q2Y5U29oTkg2NEFncDRiaHMwRUh5bWNsMkhPTnhxdUhUVlRuSDhLQ0VvMnIwekIKNm5CcWZSQTRlNjBDU2NtRk1NQXBCckVSblNPQ2hXQnhOR0hLaXd3SG50WGxIM0o0dGNXWW04eTZVVjFJMFRnTQp2ZUZYOWkrN2VtSHQyd3JzSHlRS3pFOGFSd2Rma1JKZ2lHYlVCYTJlN0FDRVdFT3B1NGoyTW9yS1VPa29jWXBRCjMrdXQwWlpBQWJTbmd4VTMwTVhiaUI4TzFqRHRCblk0VVQzYXA0VGdWa2VvR0F4dXdnRHp1UlZyVThwdjd6Q00KL1F3Tm1UaGduVERiVFBkL2ZXaVhqKytFWVprd2p0THJ4cW9BUmN0REJMQlpCQUlDWnlaTlcwM09CRVFLTG9Hcgo2c0UyVUE0ejRqQ21CcGwrdEROL1laOTBuL3NGcExVb2hZLzNjT1ZKeEFCZG1jc3BTY1dreHVLVkRlbW9Ra0Z2CkJRTWlQZHpGbGVUVmJwRVFUMEswcWhZUVFaRTZyZjQwRXJISXNtNGIxRGFTOE0veVM0b3FwMUlKL09SbCtsb0oKeXp3amZBYjd0WE05NEtFWHFvRE53QWxJbWJNV1FWT2tHWEYvbkNjaFRFWnNIaElkM3QrM3RJUUhEcyszaGFYNAo0YWM2MjNPVS9VV0hrdEMwUGVCMC91bGFSMVNZZnBmNC9zZXhmdmlTMmV3S3ZRS3orWHJjUkRDMHBjd01qMGJLCjVSYzlmMnpkVnFvcURmeWV2a3p4aXc0eHdlK1pYQy9EUmdCMFJFSnlyVzAwblJ1OTV5SklwNmhOWHg0MVpQUHQKR2hXZlZNbzRzTXVPaVV4WlpqWEZlMmhFU2JwdG5FTkVMVHZKcEhodHBkODdZcFFmdUsreFhzd1doY2NOeStWZwoyaGtSSU1wMXJSSVdSalY4OXBXbFJlc0VBa2hOalNYZ3VvMG1wUndCSVExVUV4czlVOGIxeUdnbEs4Rm1lTDA3CllSTGpid0t0NU5Ia0QydHhSNE15N0RsRjZDQmJodDJoc1V4YmFKSGZXS05NTytKNjhaUWZOWnRVREhHTDd2TUQKQ1FCTXltVmlxU3lUM2YxK1NIRTczb0xpL2JVRHRXTWF6cDNDMFdKdEI2ckVlZ3Z2aXhnVVVNbG1sZE5jYmdhOApWUUVKWHhMYXBYbXgvU2haMUlRaDlwL09NRUlBZlZ0T1VNMC84MGFGZ2hFbTV1dFlaWUl6b0xQbCs4bnZrczR6CnZJRXlCM2pEWUZlbmQwSGk0L29LQ1ZtZlhueG1aUHMvWUU0d1d5OThYbHlPNmVqWnVhOTdNZjlYeEQ2a0IvYmsKV3NKUWtQZWh4aTlqWkRvL0pPdENxUG1WZ0JCQUNmZjc0QXhGaGNDYk1Dc1B0Z0xHUlpycjE3dkt6N2pJQ2p1aAorYzJFRG8zL3Y5Ykg2d2VXSUpYSTl1RHBYdXo0TnFjWnhOcjFXSE9Pa3liRWcxalE5MVJUc1Z0M1RjMlBSTUZDClNLMjJoYkV5S1BBSUR2Y3JTakJqMHFTVHJ3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJSmtUQ0NCWG1nQXdJQkFnSVVPSkl6WnRVNlIxVksvMy9RTDFvOXVqTGF2NkV3RFFZSktvWklodmNOQVFFTApCUUF3V0RFTE1Ba0dBMVVFQmhNQ1EwRXhDekFKQmdOVkJBZ01Ba05CTVFzd0NRWURWUVFIREFKRFFURUxNQWtHCkExVUVDZ3dDUTBFeEN6QUpCZ05WQkFzTUFrTkJNUlV3RXdZRFZRUUREQXh0ZVdSdmJXRnBiaTVqYjIwd0hoY04KTWpVd05qRTJNVFExT0RJMFdoY05NelV3TmpFME1UUTFPREkwV2pCWU1Rc3dDUVlEVlFRR0V3SkRRVEVMTUFrRwpBMVVFQ0F3Q1EwRXhDekFKQmdOVkJBY01Ba05CTVFzd0NRWURWUVFLREFKRFFURUxNQWtHQTFVRUN3d0NRMEV4CkZUQVRCZ05WQkFNTURHMTVaRzl0WVdsdUxtTnZiVENDQkNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dRUEFEQ0MKQkFvQ2dnUUJBTDhWYjV6T014d3p4eWQrL25mczdKM0tIYXhYUHZkV1VySHdQQ05EdTdSUVFUN0JtRFBXdjB4eQo3N1M0NUV6dysxOTZpaHZHbHBob0VBQ2YyOHVzQjNUUzNyQXAvL2I2c1c0N3JtQWQ5RG0vcWhCSXc5WTZrWlNDCmMrbDNraE1DMnB5ZEpwdmNxVDV1SEdtVnUwYkhVVk9oSDl4SStoOU1haXR5QWVvVDhlSjhIc3cybEdYY2xyN0IKU2djSm80ckJEOHZ0MmkrbU1IOU4xUTlWbktENlJhOUpTeUpDT0p4eHhISXlHQlM2Rm1RMit1NjVwVm5UNjJqRQo2dkw4bGVGdkJSQkpySFJlZFc5bU5xdXI5ZXFxdDlBY2pleVk5S2J4RUR4Y2gxMnVXbFZiRktVUHhUdGxiMmlFCkFWTzlaR1VJTTlzMUZOL0Z3cDBucGU0WFVLZHAyN0xubDljSU9rYUFLdmZKeWdMNE8xa3AwKzg3VjhhRHlvbkkKTURWemZhQ2lKZDQ5QXo5SXFpYmpWZEh2cXlaNVFwZVM5R3Bta01DcEN0MVlsVUNTdXJmczZJR3lGeFpRVGpRQgpncE1JRFFoRExqS0FTdjRsZ1dLS3lkdXl6M0hkRWtKdDUycU0vdEJXY2JyK1ZaUllPWUtoU3BRcDZndk45KzhJClJGRmgrVXc5T1huRjBhLzZzTStUODBsSWRIQlNFWTFhS2hxUVNQMjFqTVorek9QRGdjcHlGaE5NZ2RZaTdZcVQKTnl4T0ljY2Y4bzlCS3RHZC9Ca3hUa1BvaUdndld3ZmxST2VJZS93OFU4K1pjNWVwQXBrSXdGbHJUSmhDd2FBdwp0TDYxZjh6R0NWaE83ZmNrcFlBcUlFb1RXdWxoZ1krWm5rWjRPdWhKa1JiQTVoL1duYU8xNEpTYXAveEpiMDl6CkdNTWlGL01Sa25KM0xUVTVNalNCdFdQeEt2QWsxQXl2UWRpWkNUaDJCNWFESGtvRjhQQmpUdjgrcjBueXdJaUUKMlhGZEtrTlV2MnNmZEpETU1WYlpxdXAwcmJIOWN4ZldlSXplTG15a2JmbERyb1NVU3lyV0ZwbzFLTy9aWGtEQgpESWJpWXRGUzBQUGJ2MEhzaGxhWWE3Y0RMZlEvYnFBWDdBcjVNRWNjM1dlU3ZKVVNsTUQ4NHdlVk54MnpKRVptCnJnNTd3NE5HeisySGpVOXlUSUo1amFHWW9qRktlQUxWa1JwZ1ZUN2hnR2ZMWS9HZEcvelhOVC9nMzdCTTg3S3IKN1J1YUNBY0ZzdTE4RDRJVTE4MWlrZi9PVm11dkd2OEpjYUJUQXJsZEtXWmZnd2ppUmRLamZ3MXNOSHBnR2dOOApRck9wZEFXM3ByVWR0NS9xNStiUGZqZlZpYjR6UVIvS1d3M3QyeU5LazlGeTd6VFdoelB5TDhiR0t0ZUY0bjZvCjd1Mnp4a0VBZHJPd1l2Z2tDdnF0YTdGRnVMS3VMaEhXd25Qem5nUkx1cFlLS2orSnVLdDZFREtNdStLZmhuVUMKL0hIa1lPUk1obHhvcHg2Y3VJY0IyWXJuYnlBVVMxNmFrQzQ2MXZsbDArdUFROEFCd3ZOWk1XSlZBczZoOWdNWAo5eWdmek1vY3o2UWhQa3BPMkw4TTA1VjlOWVc0b3pRVGc2dWxLbEhmMTlMd0lnRU0xQy9KYjRxSEMwRnI4SjIvCi9zdWFvcnJyZzlPNy9BWEtDM3gxQ0FFQnRNajRjdUdsbmZobk1wZlU5NW1WeitLVW5oRU5NMDdOL3ZkeGIwdGEKNnFxc1M3aWZSWU1FL1dkRmM2OE1YT3BuRVdIR2s0VUNBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGR001Qmh2NwpNejFiQnE5TEhDR21NbnNYSzRySk1COEdBMVVkSXdRWU1CYUFGR001Qmh2N016MWJCcTlMSENHbU1uc1hLNHJKCk1BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dRQkFIc1hZSFNLalVXWktIZncKVm1hc2QwLy9PN2IwSEhmK09QVy9KOVVJUFlMTkJyR3hoRHNVb3I1Uk51WkNiUGNyM0RKOXFyNmFadE5FUzRLZwoyaU02QXdJSVMyTEV0d2Njakg4bXVnUkRPbWNyUEwwMUlHVW5rZXlEWlRwRFMrMXdEL1cvMHNEVU5JVHpBWWdDClQ0TWh5emdpRWhqTjB3TlkreGpzOUU1RS9QZVh6R3EyODkwTnI1Y3V1ck01R1o4SXR4M3BqSUJoUjVXWFhqdU0Kb1dvdG8zckZrZzhrVE44b2pjZWd6T1FoU2NOQUkyRFZLNVlEOGZWTkwvOG1OSEN3QmFEbGdXcUxIL09IM0M5TwpWN1ZHczladDhRNC9Rcjc1ODNpaVo5b1ozN1RUVk94UnJYZlk0TUs0RFRRWlVnTlpHaXNWcjVqUzZJaGRrMUZFCmJzL0crOFBWdXQ0OGN2TXRGYnJaK29NTDBnL0M0NTdxR0pWeXE0L2xQUzJRNXNOUnhpK2x5RHMxUm96eTMxMWMKSU5mMXk4OFR4L3hXemYzRjBHMHh0KzVJUWpFSUhGOHpkcTRNck45d1NsbjVHUm51Yyt0aHVEMDJERVI3dHJ2TgpQVzc4cVpob2VTZjlKZWVxSmFEclJxaDh3OGRQRW4vblFYU0F4UWlIYzc0dmZsSlFFVVFXUTl6di9JZEJOdThxCnVvWXQrc2JKN3VWRDJUdzNxZVNPdzhleHBTVEp2VXdyWGVVcXJzRGhvaFd3ai9WakwveEZRWlg3OFlvbHFJTW4KOUVIMGtJZm5taHZuTHdpWGNQcVR6amhReENXdlpwVnhJYzV2blAwRUtHbmhOVWpjenBMQjdCTit5OThYWEpVbwovSlFCTjFNOFErZHh0VXVGL280aGxuUUlBT0N1Vm1kT2l5TkU4YjdwNklFMTlMaytKNFpkOUhIbXA0VXptMUJKCkhRWDh2SFdSTk4zUHZubTVCVnJVcUcyckk4Zm5ldm1iNnhxR2Zrc3VNWlpRTC9UWmJoSEFPRUVwODlvWlRic28KUW5KbE9ibkNuTTl2YXlzWEVVazVhOEZnTlNReUE4YnNGNWxrSkdzb2dnampmMlBaSDlYMjFuSFAvUHhoM0VSUQpSdm1XQjNaUjBNMFZ0eXdOMmFtTVp2by9wejluNTlOSG8vUHl2RkovZndUeW1HbUp1QldzSW9RTG1XS2duRnY1CjN1Rm12MWRHRGpka2dGVjFyK3R0eFJubUhNajZWL2w5L3FFNERyajlKYzlESC9OQmNYVktGbkRMUURjT1MyR1MKSW5NMWluQ3U1alJTYzJETHJ5L2R4UHk2eDRpVlZqajVzRS9tUktvMHJ2UEIzeU1MdGdXQkRpQmJhT3JxTGN2bApKeUg5YTRkUUJRYmNrUkV0Z25zRDcvandLRVFmWml5ak5td2kxVnlsVzZOdTBxMjBPMnVUV0owN3BFMTBGS0FRCmhwWDh5Q2NmcXg0dFZYZmNDV3Z6Mm1rdml3TkYxa00xRUdVTWlmczNIei9oVWl6bHhUZmlNK2YxL0lNakZFWWwKZ1RlL0lvQnFCUEk3YjdhRWxFckdqcXRBM0MrQklaL1hQbEwxL3doMGp2dldteWp6Nk5Id1dIV1lEOUdGbkpPNQpWd3BFcXRwQm1ONCtDd1lpT2tXQTlnbks1eXBiNVQ2RVVtWml0TU15U0ZhZi9aU0ZYcUdWd0RtdXc2REYxUUFtCkFyV2cyNGV0dVJzMVp4ZHRGRFdEZHpzTER3L1VLYlYvbWdTeXo4cDlndEduOTdodW9waitwdmJBNXd3MklUNEgKY0U0QVVKMD0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="

            action_params = {
                "certificate": request.get("certificate"),
                "ca-chain": new_ca_chain,
                "ca-certificate": self.ca_cert,
                "certificate-signing-request": str(csr),
            }

            LOG.debug(f"Running action {action_cmd} with params {action_params}")
            try:
                action_result = run_sync(
                    self.jhelper.run_action(unit, self.model, action_cmd, action_params)
                )
            except ActionFailedException as e:
                LOG.debug(f"Running action {action_cmd} on {unit} with params {action_params} failed")
                return Result(ResultType.FAILED, str(e))

            LOG.debug(f"Result from action {action_cmd}: {action_result}")
            if action_result.get("return-code", 0) > 1:
                return Result(
                    ResultType.FAILED, f"Action {action_cmd} on {unit} returned error"
                )

        return Result(ResultType.COMPLETED)


class VaultTlsFeature(TlsFeature):
    version = Version("0.0.1")

    name = "tls.vault"
    tf_plan_location = TerraformPlanLocation.SUNBEAM_TERRAFORM_REPO

    def config_type(self) -> type | None:
        """Return the config type for the feature."""
        return VaultTlsFeatureConfig

    def default_software_overrides(self) -> SoftwareConfig:
        """Feature software configuration."""
        return SoftwareConfig(
            charms={"manual-tls-certificates": CharmManifest(
                channel="1/edge")}
        )

    def manifest_attributes_tfvar_map(self) -> dict:
        """Manifest attributes terraformvars map."""
        return {
            self.tfplan: {
                "charms": {
                    "manual-tls-certificates": {
                        "channel": "manual-tls-certificates-channel",
                        "revision": "manual-tls-certificates-revision",
                        "config": "manual-tls-certificates-config",
                    }
                }
            }
        }

    def preseed_questions_content(self) -> list:
        """Generate preseed manifest content."""
        certificate_question_bank = questions.QuestionBank(
            questions=certificate_questions("unit", "subject"),
            console=console,
            previous_answers={},
        )
        content = questions.show_questions(
            certificate_question_bank,
            section="certificates",
            subsection="<CSR x500UniqueIdentifier>",
            section_description="TLS Certificates",
            comment_out=True,
        )
        return content

    @click.command()
    @click.option(
        "--endpoint",
        "endpoints",
        multiple=True,
        default=["public"],
        type=click.Choice(["public", "internal", "rgw"], case_sensitive=False),
        help="Specify endpoints to apply tls.",
    )
    @click.option(
        "--ca-chain",
        required=True,
        type=str,
        callback=validate_ca_chain,
        help="Base64 encoded CA Chain certificate",
    )
    @click.option(
        "--ca",
        required=True,
        type=str,
        callback=validate_ca_certificate,
        help="Base64 encoded CA certificate",
    )
    @click_option_show_hints
    @pass_method_obj
    def enable_cmd(
        self,
        deployment: Deployment,
        ca: str,
        ca_chain: str,
        endpoints: list[str],
        show_hints: bool,
    ):
        """Enable TLS Vault feature."""
        # Check if vault is enabled

        self.pre_enable(deployment, VaultTlsFeatureConfig, show_hints)
        self.enable_feature(
            deployment,
            VaultTlsFeatureConfig(ca=ca, ca_chain=ca_chain, endpoints=endpoints),
            show_hints,
        )

    @click.command()
    @click_option_show_hints
    @pass_method_obj
    def disable_cmd(self, deployment: Deployment, show_hints: bool):
        """Disable TLS Vault feature."""
        self.disable_feature(deployment, show_hints)
        console.print("TLS Vault feature disabled")

    def set_application_names(self, deployment: Deployment) -> list:
        """Application names handled by the terraform plan."""
        return ["manual-tls-certificates"]

    def set_tfvars_on_enable(
        self, deployment: Deployment, config: VaultTlsFeatureConfig
    ) -> dict:
        """Set terraform variables to enable the application."""
        tfvars: dict[str, str | bool] = {
            "traefik-to-tls-provider": CA_APP_NAME}
        if "public" in config.endpoints:
            tfvars.update({"enable-tls-for-public-endpoint": True})
        if "internal" in config.endpoints:
            tfvars.update({"enable-tls-for-internal-endpoint": True})
        if "rgw" in config.endpoints:
            tfvars.update({"enable-tls-for-rgw-endpoint": True})

        return tfvars

    def set_tfvars_on_disable(self, deployment: Deployment) -> dict:
        """Set terraform variables to disable the application."""
        tfvars: dict[str, None | str | bool] = {
            "traefik-to-tls-provider": None}
        provider_config = self.provider_config(deployment)
        endpoints = provider_config.get("endpoints", [])
        if "public" in endpoints:
            tfvars.update({"enable-tls-for-public-endpoint": False})
        if "internal" in endpoints:
            tfvars.update({"enable-tls-for-internal-endpoint": False})
        if "rgw" in endpoints:
            tfvars.update({"enable-tls-for-rgw-endpoint": False})

        return tfvars

    def set_tfvars_on_resize(
        self, deployment: Deployment, config: FeatureConfig
    ) -> dict:
        """Set terraform variables to resize the application."""
        return {}

    @click.group()
    def tls_group(self) -> None:
        """Manage TLS."""

    @click.group()
    def ca_group(self) -> None:
        """Manage CA."""

    @click.command()
    @click.option(
        "--format",
        type=click.Choice([FORMAT_TABLE, FORMAT_YAML]),
        default=FORMAT_TABLE,
        help="Output format",
    )
    @pass_method_obj
    def list_outstanding_csrs(self, deployment: Deployment,
                              format: str) -> None:
        """List outstanding CSRs."""
        app = "manual-tls-certificates"
        model = OPENSTACK_MODEL
        action_cmd = "get-outstanding-certificate-requests"
        jhelper = JujuHelper(deployment.get_connected_controller())
        try:
            action_result = get_outstanding_certificate_requests(
                app, model, jhelper)
        except LeaderNotFoundException as e:
            LOG.debug(f"Unable to get {app} leader to print CSRs")
            raise click.ClickException(str(e))
        except ActionFailedException as e:
            LOG.debug(f"Running action {action_cmd} failed")
            raise click.ClickException(str(e))

        LOG.debug(f"Result from action {action_cmd}: {action_result}")
        if action_result.get("return-code", 0) > 1:
            raise click.ClickException(
                "Unable to get outstanding certificate requests from CA"
            )

        certs_to_process = json.loads(action_result.get("result", "[]"))
        csrs = {
            relation: csr
            for record in certs_to_process
            if (relation := str(record.get("relation_id"))) and (csr := record.get("csr"))
        }

        if format == FORMAT_TABLE:
            table = Table()
            table.add_column("Relation ID")
            table.add_column("CSR")
            for relation, csr in csrs.items():
                table.add_row(relation, csr)
            console.print(table)
        elif format == FORMAT_YAML:
            yaml.add_representer(str, str_presenter)
            console.print(yaml.dump(csrs))

    @click.command()
    @click.option(
        "-m",
        "--manifest",
        "manifest_path",
        help="Manifest file.",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
    )
    @click_option_show_hints
    @pass_method_obj
    def configure(
        self,
        deployment: Deployment,
        manifest_path: Path | None = None,
        show_hints: bool = False,
    ) -> None:
        """Configure Unit certs."""
        client = deployment.get_client()
        manifest = deployment.get_manifest(manifest_path)
        preseed = {}
        if (ca := manifest.get_feature(
             self.name.split(".")[-1])) and ca.config:
            preseed = ca.config.model_dump(by_alias=True)
        model = OPENSTACK_MODEL
        apps_to_monitor = [CA_APP_NAME]

        try:
            config = read_config(client, CERTIFICATE_FEATURE_KEY)
        except ConfigItemNotFoundException:
            config = {}
        ca = config.get("ca")
        ca_chain = config.get("chain")

        if ca is None or ca_chain is None:
            raise click.ClickException("CA and CA Chain not configured")

        jhelper = JujuHelper(deployment.get_connected_controller())
        plan = [
            AddManifestStep(client, manifest_path),
            ConfigureVaultCAStep(
                client,
                jhelper,
                ca,
                ca_chain,
                deployment_preseed=preseed,
            ),
            # On ingress change, the keystone takes time to update the service
            # endpoint, update the identity-service relation data on every
            # related application.
            WaitForApplicationsStep(
                jhelper, apps_to_monitor, model,
                INGRESS_CHANGE_APPLICATION_TIMEOUT
            ),
        ]
        run_plan(plan, console, show_hints)
        click.echo("CA certs configured")

    def enabled_commands(self) -> dict[str, list[dict]]:
        """Dict of clickgroup along with commands.

        Return the commands available once the feature is enabled.
        """
        return {
            "init": [{"name": self.group.name, "command": self.tls_group}],
            "init.tls": [{"name": "vault", "command": self.ca_group}],
            "init.tls.vault": [
                {"name": "unit_certs", "command": self.configure},
                {
                    "name": "list_outstanding_csrs",
                    "command": self.list_outstanding_csrs,
                },
            ],
        }

    def is_vault_application_active(self, jhelper: JujuHelper) -> bool:
        """Check if Vault application is active."""
        model = run_sync(jhelper.get_model(OPENSTACK_MODEL))
        try:
            application = run_sync(jhelper.get_application("vault", model))
        except SunbeamException:
            raise click.ClickException(
                "Cannot enable TLS Vault as Vault is not enabled."
                "Enable Vault first.")
        status = application.status
        run_sync(model.disconnect())
        if status == "active":
            return True
        elif status == "blocked":
            raise click.ClickException(
                "Vault application is blocked. Initialize and authorize "
                "Vault first.")
        return False

    def _get_relations(self, model: str, endpoints: list[str]) -> list[tuple]:
        """Return model relations for the provided endpoints."""
        relations = []
        model_status = run_sync(self.jhelper.get_model_status(model))
        model_relations = [r.get("key") for r in model_status.get("relations", {})]
        for endpoint in endpoints:
            for relation in model_relations:
                if endpoint in relation:
                    relations.append(tuple(relation.split(" ")))
                    break

        return relations

    def is_tls_ca_enabled(self, jhelper: JujuHelper) -> bool:
        """Check if TLS CA feature was enabled."""
        model = run_sync(jhelper.get_model(OPENSTACK_MODEL))
        try:
            tls_app = run_sync(jhelper.get_application(
                "manual-tls-certificates", model))
        except SunbeamException:
            return True
        relations = self._get_relations(
            OPENSTACK_MODEL, tls_app.get("endpoints", []))
        if not relations:
            LOG.debug("No relations found for TLS CA endpoints")
            run_sync(model.disconnect())
            return True
        # Check for relation between manual-tls-certificates:certificates and traefik, traefik-public, or traefik-rgw
        cert_apps = ["traefik", "traefik-public", "traefik-rgw"]
        for relation in relations:
            if ("manual-tls-certificates:certificates" in relation and any(
                 app in relation for app in cert_apps)):
                run_sync(model.disconnect())
                return True
        run_sync(model.disconnect())
        return False

    def pre_enable(
        self, deployment: Deployment, config: ConfigType, show_hints: bool
    ) -> None:
        """Handler to perform tasks before enabling the feature."""
        super().pre_enable(deployment, config, show_hints)
        jhelper = JujuHelper(deployment.get_connected_controller())
        if not self.is_vault_application_active(jhelper):
            raise click.ClickException(
                "Cannot enable TLS Vault as Vault is not enabled."
                "Enable Vault first."
            )
        if not self.is_tls_ca_enabled(jhelper):
            raise click.ClickException(
                "Cannot enable TLS Vault as TLS CA is already enabled."
            )


def regenerate_ca_chain(old_chain_b64: str, new_cert_b64: str) -> str:
    """
    Combine the first certificate from old_chain_b64 with the new certificate in new_cert_b64,
    returning a Base64-encoded PEM chain.
    """
    # 1. Decode inputs
    old_chain_pem = base64.b64decode(old_chain_b64)
    new_cert_pem = base64.b64decode(new_cert_b64)

    # 2. Extract the first certificate (including BEGIN/END lines)
    all_certs = re.findall(
        b"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        old_chain_pem,
        flags=re.DOTALL
    )
    if not all_certs:
        raise ValueError("No PEM certificates found in old_chain_b64")
    bottom_cert_pem = all_certs[-1]

    # 3. Combine them (ensure a newline between)
    combined = bottom_cert_pem.rstrip(b"\n") + b"\n" + new_cert_pem.strip(b"\n") + b"\n"

    # 4. Re-encode to Base64 (no line wraps)
    return base64.b64encode(combined).decode('ascii')
