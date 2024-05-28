
import asyncio
import typing
import aiohttp

import settings
from utils.custom_models import (
    URLsSettings, URLSettings, VirusTotalModel, BlackListChecker
)
from pydantic import ValidationError


class AsyncRequester:
    """
    Summary:
        Make async requests to notifications api.
    """
    def __init__(
        self,
        url_models: URLsSettings,
    ) -> None:
        """
        Summary:
            Perform main requests.

        Args:
            url_models (URLsSettings): set of the URL settings.
        """
        self.url_models = url_models

    async def perform_code_request(
        self,
        session: aiohttp.ClientSession,
        url: URLSettings,
    ) -> None:
        """
        Summary:
            Get notifications from endpoint.

        Args:
            session (aiohttp.ClientSession): Object of interface
            for http requests.
            url (URLSettings): Settings of the URL.
        """
        async with session.request(
            'GET',
            url=str(url.url),
            headers={
                "Content-Type": "application/json",
                "accept": "application/json"
            },
            timeout=5
        ) as response:
            url.status_code = response.status

    async def pefrom_cert_request(
        self,
        session: aiohttp.ClientSession,
        url: URLSettings
    ):
        """
        Summary:
            Perfom request to check certificate.

        Args:
            session (aiohttp.ClientSession): Object of interface
            for http requests
            url (URLSettings): Settings of the URL.
        """
        if url.scheme and url.scheme.name == "HTTP":
            return
        try:
            async with session.request(
                'GET',
                url=str(url.url),
                headers={
                    "Content-Type": "application/json",
                    "accept": "application/json"
                },
                timeout=5
            ) as response:
                if response.status == 200:
                    url.ssl_certificate = "Valid"
                else:
                    url.ssl_certificate = "Invalid"
        except aiohttp.ClientSSLError as e:
            url.ssl_certificate = "Invalid or cannot be verified."
            print("SSL certificate is invalid or cannot be verified.", f"My error is {e}")
        except aiohttp.ClientError as e:
            print("Error:", e)

    async def get_virustotal_scan_id(
        self,
        session: aiohttp.ClientSession,
        url: URLSettings
    ):
        """
        Summary:
            Get resource scan id.

        Args:
            session (aiohttp.ClientSession): Object of interface
            url (URLSettings): Settings of the URL.
        """
        data = {
            'apikey': settings.VIRUS_TOTAL_API_KEY, 'url': str(url.url)
        }
        try:
            async with session.request(
                'POST',
                url=settings.VIRUS_TOTAL_SCAN_URL,
                data=data,
                timeout=5,
            ) as response:
                response_data = await response.json()
                if response_data:
                    if response_data.get('response_code') == 1:
                        try:
                            model_data = VirusTotalModel(
                                valid_response=True,
                                message=response_data.get(
                                    "verbose_msg",
                                    "URL found in VirusTotal's database."
                                ),
                                scan_id=response_data.get('scan_id')
                            )
                        except ValidationError as _:
                            model_data = VirusTotalModel(
                                valid_response=False,
                                message=response_data.get(
                                    "verbose_msg",
                                    ("Data types have changed, "
                                     "model need to be updated.")
                                )
                            )
                        url.virustotal = model_data
                    else:
                        model_data = VirusTotalModel(
                            valid_response=True,
                            message=response_data.get(
                                "verbose_msg",
                                "URL not found in VirusTotal's database."
                            )
                        )
                        url.virustotal = model_data
                else:
                    print("Failed to make request to VirusTotal API.")
        except aiohttp.ClientError as e:
            print("Error:", e)

    async def get_virustotal_report(
        self,
        session: aiohttp.ClientSession,
        url: URLSettings
    ):
        """
        Summary:
            Get report by scan id.

        Args:
            session (aiohttp.ClientSession): Object of interface
            url (URLSettings): Settings of the URL.
        """
        if not url.virustotal.scan_id:
            return
        params = {
            'apikey': settings.VIRUS_TOTAL_API_KEY,
            'resource': str(url.virustotal.scan_id)
        }
        try:
            async with session.request(
                'GET',
                url=settings.VIRUS_TOTAL_REPORT_URL,
                params=params,
                timeout=5,
            ) as response:
                response_data = await response.json()
                if response_data:
                    if response_data.get('response_code') == 1:
                        try:
                            url.virustotal.valid_response = True
                            url.virustotal.message = response_data.get(
                                "verbose_msg",
                                "URL found in VirusTotal's database."
                            )
                            url.virustotal.permalink = response_data.get(
                                'permalink', 'N/A'
                            )
                            url.virustotal.positives = response_data.get(
                                'positives', 0
                            )
                            url.virustotal.response_code = response_data.get(
                                'response_code', 0
                            )
                            url.virustotal.scan_date = response_data.get(
                                'scan_date', 'N/A'
                            )
                            url.virustotal.scans = response_data.get(
                                'scans', {}
                            )
                            url.virustotal.total = response_data.get(
                                'total', 0
                            )
                            url.virustotal.url = response_data.get(
                                'url', 'N/A'
                            )
                        except ValidationError as _:
                            url.virustotal.valid_response = False
                            url.virustotal.message = response_data.get(
                                "verbose_msg",
                                ("Data types have changed, "
                                    "model need to be updated.")
                            )
                    else:
                        url.virustotal.valid_response = True
                        url.virustotal.message = response_data.get(
                            "verbose_msg",
                            "URL not found in VirusTotal's database."
                        )
                else:
                    print("Failed to make request to VirusTotal API.")
        except aiohttp.ClientError as e:
            print("Error:", e)

    async def perform_blacklist_checker_request(
        self,
        session: aiohttp.ClientSession,
        url: URLSettings
    ):
        """
        Summary:
            Perform request to BlackListChecker API.

        Args:
            session (aiohttp.ClientSession): Object of interface
            url (URLSettings): Settings of the URL.
        """
        if not url.ip and not url.domain:
            return
        ip_or_domain = url.ip if url.ip else url.domain
        full_url = f"{settings.BLACKLIST_CHECKER_URL}{ip_or_domain}"
        try:
            async with session.request(
                'GET',
                url=full_url,
                auth=aiohttp.BasicAuth(settings.BLACKLIST_CHECKER_API_KEY, ''),
                timeout=5,
            ) as response:
                response_data = await response.json()
                if response_data:
                    try:
                        model_data = BlackListChecker(
                            valid_response=True,
                            message=(
                                "URL found in BlackListChecker database."
                            ),
                            status=response_data.get("status", "N/A"),
                            input_raw=response_data.get("input_raw", "N/A"),
                            input_type=response_data.get("input_type", "N/A"),
                            input_domain=response_data.get(
                                "input_domain",
                                "N/A"
                            ),
                            ip_address=response_data.get("ip_address", "N/A"),
                            detections=response_data.get("detections", 0),
                            blacklists=response_data.get("blacklists", []),
                            checks_remaining=response_data.get(
                                "checks_remaining",
                                0
                            )
                        )
                    except ValidationError as _:
                        model_data = BlackListChecker(
                            valid_response=False,
                            message=("Data types have changed, model "
                                    "need to be updated.")
                        )
                    url.blacklist_checker = model_data
                else:
                    print("Failed to make request to BlackListChecker API.")
        except aiohttp.ClientError as e:
            print("Error:", e)

    async def gather_data(self, func: typing.Callable, ssl=False):
        """
        Summary:
            Gather async tasks.
        """
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl)
        ) as session:
            tasks = []
            for url in self.url_models.urls:
                task = asyncio.create_task(func(
                    session,
                    url
                ))
                tasks.append(task)
            await asyncio.gather(*tasks)

    def check_url_statuses(self):
        """
        Summary:
            Check status codes of urls.
        """
        asyncio.run(self.gather_data(self.perform_code_request))

    def check_url_certs(self):
        """
        Summary:
            Check certs of urls.
        """
        asyncio.run(self.gather_data(self.pefrom_cert_request, ssl=True))

    def virustotal_check(self):
        """
        Summary:
            Check URL with VirusTotal service.
        """
        asyncio.run(self.gather_data(self.get_virustotal_scan_id))
        asyncio.run(self.gather_data(self.get_virustotal_report))

    def blacklist_checker_check(self):
        """
        Summary:
            Check IP address with BlackListChecker service.
        """
        asyncio.run(
            self.gather_data(self.perform_blacklist_checker_request)
        )
