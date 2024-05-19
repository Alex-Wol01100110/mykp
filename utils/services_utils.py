
import whois
from .custom_models import URLsSettings, WhoIsModel
from .request_utils import AsyncRequester
from .url_utils import get_url_scheme, get_url_domain, get_domain_ip
from pydantic import ValidationError


def get_website_status_codes(urls: URLsSettings):
    """
    Summary:
        Make async requests to notifications api.

    Args:
        url (str): Url.

    Returns:
        int: Website status code.
    """
    async_requester = AsyncRequester(urls)
    async_requester.check_url_statuses()

def get_whois_info(url_models: URLsSettings):
    for url in url_models.urls:
        whois_data = whois.whois(str(url.url))
        try:
            whois_obj = WhoIsModel(
                valid_response=True,
                domain_name=tuple(
                    whois_data.domain_name
                    if isinstance(whois_data.domain_name, list)
                    else [whois_data.domain_name]
                ),
                creation_date=tuple(
                    whois_data.creation_date
                    if isinstance(whois_data.creation_date, list)
                    else [whois_data.creation_date]
                ),
                expiration_date=tuple(
                    whois_data.expiration_date
                    if isinstance(whois_data.expiration_date, list)
                    else [whois_data.expiration_date]
                ),
                updated_date=tuple(
                    whois_data.updated_date
                    if isinstance(whois_data.updated_date, list)
                    else [whois_data.updated_date]
                )
            )
        except ValidationError as _:
            whois_obj = WhoIsModel(
                valid_response=False
            )
        url.whois_data = whois_obj

def get_website_main_infos(url_models: URLsSettings):
    for url in url_models.urls:
        url.scheme = get_url_scheme(url.url)
        url.domain = get_url_domain(url.url)
        if url.status_code == 200:
            url.ip = get_domain_ip(url.domain)

def perform_services_checks(url_models: URLsSettings) -> URLsSettings:
    async_requester = AsyncRequester(url_models)
    async_requester.check_url_statuses()
    get_website_main_infos(url_models)
    async_requester.check_url_certs()
    get_whois_info(url_models)
    async_requester.virustotal_check()
    async_requester.blacklist_checker_check()
    return url_models
