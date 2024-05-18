
from pydantic import AnyUrl, BaseModel
from typing import Optional
from enum import Enum


class URLScheme(Enum):
    HTTP = 'http'
    HTTPS = 'https'


class WhoIsModel(BaseModel):
    """
    Summary:
        Model for data from whois service.
    """
    valid_response: Optional[bool] = None
    domain_name: Optional[tuple] = None
    creation_date: Optional[tuple] = None
    expiration_date: Optional[tuple] = None
    updated_date: Optional[tuple] = None


# class VirusTotalModel(BaseModel):
#     valid_response: Optional[bool] = None
#     message: Optional[str] = None
#     scan_date: Optional[str] = None
#     total: Optional[int] = None
#     positives: Optional[int] = None
#     scans: Optional[dict] = None


class VirusTotalModel(BaseModel):
    valid_response: Optional[bool] = False
    message: Optional[str] = None
    permalink: Optional[str] = None
    positives: Optional[int] = None
    response_code: Optional[int] = None
    scan_date: Optional[str] = None
    scan_id: Optional[str] = None
    scans: Optional[dict] = None
    total: Optional[int] = None
    url: Optional[str] = None


class BlackListChecker(BaseModel):
    valid_response: Optional[bool] = False
    message: Optional[str] = None
    status: Optional[str] = None
    input_raw: Optional[str] = None
    input_type: Optional[str] = None
    input_domain: Optional[str] = None
    ip_address: Optional[str] = None
    detections: Optional[int] = None
    blacklists: Optional[list] = None
    checks_remaining: Optional[int] = None


class URLSettings(BaseModel):
    """
    Summary:
        Set base model of the URL configuration.
    """
    url: AnyUrl
    status_code: Optional[int] = None
    scheme: Optional[URLScheme] = None
    domain: Optional[str] = None
    ip: Optional[str] = None
    ssl_certificate: Optional[str] = "Unknown"
    whois_data: Optional[WhoIsModel] = None
    virustotal: Optional[VirusTotalModel] = None
    blacklist_checker: Optional[BlackListChecker] = None


class URLsSettings(BaseModel):
    """
    Summary:
        Set base model of the URL configuration.
    """
    urls: tuple[URLSettings, ...]
