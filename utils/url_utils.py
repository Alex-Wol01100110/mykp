import re
import subprocess
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

def get_url_ip(domain: str) -> str:
    """
    Summary:
        Get url ip.

    Args:
        url (str): Url.

    Returns:
        str: Ip.
    """
    with subprocess.Popen(
        ["ping", '-n', '1', domain],
        stdout=subprocess.PIPE
    ) as proc:
        output = proc.stdout.read()
    result = output.decode(encoding='utf-8', errors='strict')
    result = re.sub(r'\n', '', result)
    result = re.sub(r'\r', '', result)
    result = re.findall(
        r'\[(\d+\.\d+\.\d+\.\d+)\]\swith',
        result
    )
    if result:
        return result[0]
    return 'N/A'
