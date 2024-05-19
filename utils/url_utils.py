import socket
from urllib.parse import urlparse
from pydantic import AnyUrl
from .custom_models import URLScheme


def get_url_scheme(url: AnyUrl) -> URLScheme:
    """
    Summary:
        Get url scheme.

    Args:
        url (str): Url.

    Returns:
        str: Scheme.
    """
    if urlparse(str(url)).scheme == "http":
        return URLScheme.HTTP
    return URLScheme.HTTPS

def get_url_domain(url: AnyUrl) -> str:
    """
    Summary:
        Get url domain.

    Args:
        url (str): Url.

    Returns:
        str: Domain.
    """
    return urlparse(str(url)).netloc

def get_domain_ip(domain: str) -> str:
    """
    Summary:
        Get IP by domain name.

    Args:
        domain (str): domain name.

    Returns:
        str: IP.
    """
    return socket.gethostbyname(domain)
