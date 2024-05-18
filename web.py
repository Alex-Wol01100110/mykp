"""Web application."""
import secrets
from typing import Dict

import uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from loguru import logger
from pydantic import ValidationError, AnyUrl, BaseModel

import settings
from utils.general_utils import ModelUtils
from utils.visualization_utils import get_visualizations_data
from utils.services_utils import perform_services_checks
from utils.custom_models import URLsSettings, URLSettings, BlackListChecker, VirusTotalModel, WhoIsModel, URLScheme
from utils.custom_filters import underscore_to_whitespace, any_to_str


app = FastAPI(
    title="Cyber Analyzer",
    description="Helps you analyze URLs in real time.",
    version="0.0.1",
    contact={
        "name": "Cyber Analyzer",
        "url": settings.WEBSITE_ADDRESS
    }
)
app.mount("/static", StaticFiles(directory="static"), name="static")
security = HTTPBasic()
templates = Jinja2Templates(directory="templates")
templates.env.filters["underscore_to_whitespace"] = underscore_to_whitespace
templates.env.filters["any_to_str"] = any_to_str


class FormModel(BaseModel):
    url: str
    additional_checks: bool


def validate_credentials(
    credentials: HTTPBasicCredentials = Depends(security, use_cache=False)
) -> bool:
    """
    Summary:
        Check if provided credentials valid.

    Args:
        credentials (HTTPBasicCredentials, optional): username and password.

    Raises:
        HTTPException: Invalid username or password.

    Returns:
        bool: Show if credentials is valid.
    """
    input_user_name = credentials.username.encode("utf-8")
    input_password = credentials.password.encode("utf-8")

    is_username = secrets.compare_digest(
        input_user_name, settings.USER_NAME.encode("utf-8")
    )
    is_password = secrets.compare_digest(
        input_password, settings.USER_PASS.encode("utf-8")
    )
    if is_username and is_password:
        return True
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Basic"}
    )


class URLs(FastAPI):
    """
    Summary:
        Provide list of endpoints.
    """

    @app.post("/test_urls/")
    async def test_urls(
        urls: tuple[AnyUrl, ...],
        authenticated: str = Depends(validate_credentials)
    ) -> Dict[str, str]:
        """
        Summary:
            Test URLs status - safe or malicious.

        Args:
            urls (str): provided urls.
            authenticated (str, optional): Bool value,
            that show if authentication is successful.

        Returns:
            Dict: key - url, value - status of url - safe or malicious..
        """
        statuses = {True: "URL is Malicious", False: "URL is Safe"}
        if authenticated:
            checked_urls = {
                str(url): statuses.get(ModelUtils.test_url(str(url)))
                for url in urls
            }
            return checked_urls
        return {"message": "User is not authenticated"}

    @logger.catch
    @app.get("/", include_in_schema=False, response_class=HTMLResponse)
    async def get_index(request: Request):
        """
        Summary:

        Args:
            request (Request): request instance.

        Returns:
            TemplateResponse
        """
        response_data = get_visualizations_data()
        response_data.update({"request": request})
        # response_data.update({"scan_result_exist": True, "scan_result": ["aalalalalalal"]})
        # response_data.update({"checked_url": "URL is Malicious", "scan_result_exist": True, "scan_result": {"urls": [{}]}, "provided_url": "https://css-tricks.com/snippets/css/prevent-long-urls-from-breaking-out-of-container/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/dhwajkhdjk/"})
        # response_data.update({"error_message": "Invalid URL"})
        response = templates.TemplateResponse(
            "index.html",
            response_data
        )
        return response

    @logger.catch
    @app.post("/", include_in_schema=False, response_class=HTMLResponse)
    def post_index(
        request: Request,
        url: str = Form(...),
        additional_checks: bool = Form(False),
        authenticated: bool = Depends(validate_credentials, use_cache=False)
    ):
        """Summary:

        Args:
            request (Request): request instance.
            url (str, optional): provided url.
            authenticated (str, optional): auth checks.

        Returns:
            TemplateResponse
        """
        statuses = {True: "URL is Malicious", False: "URL is Safe"}
        if authenticated:
            error_message = None
            checked_url = None
            services_checks = None
            scan_result_exist = False
            try:
                AnyUrl(url=url)
            except ValidationError:
                error_message = "Invalid URL"
            else:
                checked_url = statuses.get(
                    ModelUtils.test_url(url)
                )
                scan_result_exist = True
                # if additional_checks:
                    # services_checks = perform_services_checks(
                    #     URLsSettings(urls=(URLSettings(url=url),))
                    # )
                    # services_checks = services_checks.model_dump()
            
            from datetime import datetime, timedelta
            whois_data=WhoIsModel(
                valid_response=False,
                domain_name=tuple(["google.com"]),
                creation_date=tuple([(datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")]),
                expiration_date=tuple([(datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")]),
                updated_date=tuple([(datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")])
            )
            virustotal=VirusTotalModel(
                valid_response=True,
                message="Test message",
                permalink="https://kinokrad.film/",
                positives=0,
                response_code=1,
                scan_date="41241231231",
                scan_id="41241231231",
                scans={},
                total=5,
                url="https://kinokrad.film/",
            )
            blacklist_checker=BlackListChecker(
                valid_response=True,
                message="Test message",
                status="Ok",
                input_raw="127.0.0.1",
                input_type="IP",
                input_domain="None",
                ip_address="127.0.0.1",
                detections=0,
                blacklists=[],
                checks_remaining=50,
            )
            url_obj = URLSettings(
                url=url,
                status_code=200,
                scheme=URLScheme.HTTPS,
                domain="google.com",
                ip="127.0.0.1",
                ssl_certificate="Valid",
                whois_data=whois_data,
                virustotal=None,
                blacklist_checker=None
            )
            services_checks = URLsSettings(urls=(url_obj,))
            # services_checks = {"urls": [{"url": "https://kinokrad.film/466421-madame-web.html", "status_code": 200, "scheme": "https", "domain": "kinokrad.film", "ip": "172.67.199.131", "ssl_certificate": "Valid", "whois_data": {"valid_response": "True", "domain_name": ["kinokrad.film"], "creation_date": "[datetime.datetime(2024, 4, 7, 10, 15, 48), datetime.datetime(2024, 4, 7, 10, 15, 48, 220000)]", "expiration_date": "[datetime.datetime(2025, 4, 7, 10, 15, 48), datetime.datetime(2025, 4, 7, 10, 15, 48, 220000)]", "updated_date": "[datetime.datetime(2024, 4, 12, 10, 15, 48), datetime.datetime(1, 1, 1, 0, 0)]"}, "virustotal": {"valid_response": "True", "message": "Scan finished, scan information embedded in this object", "permalink": "https://www.virustotal.com/gui/url/ac3fc59c755eb209dcefafca18fd3d0c96914a236b67fb85cb08d1476eb1642a/detection/u-ac3fc59c755eb209dcefafca18fd3d0c96914a236b67fb85cb08d1476eb1642a-1716029076", "positives": 0, "response_code": 1, "scan_date": "2024-05-18 10:44:36", "scan_id": "ac3fc59c755eb209dcefafca18fd3d0c96914a236b67fb85cb08d1476eb1642a-1716029076", "scans": {"0xSI_f33d": {"detected": "False", "result": "unrated site"}, "ADMINUSLabs": {"detected": "False", "result": "clean site"}, "AILabs (MONITORAPP)": {"detected": "False", "result": "clean site"}, "Abusix": {"detected": "False", "result": "clean site"}, "Acronis": {"detected": "False", "result": "clean site"}, "AlienVault": {"detected": "False", "result": "clean site"}, "AlphaSOC": {"detected": "False", "result": "unrated site"}, "Antiy-AVL": {"detected": "False", "result": "clean site"}, "ArcSight Threat Intelligence": {"detected": "False", "result": "unrated site"}, "Artists Against 419": {"detected": "False", "result": "clean site"}, "AutoShun": {"detected": "False", "result": "unrated site"}, "Bfore.Ai PreCrime": {"detected": "False", "result": "unrated site"}, "BitDefender": {"detected": "False", "result": "clean site"}, "Bkav": {"detected": "False", "result": "unrated site"}, "BlockList": {"detected": "False", "result": "clean site"}, "Blueliv": {"detected": "False", "result": "clean site"}, "CINS Army": {"detected": "False", "result": "clean site"}, "CMC Threat Intelligence": {"detected": "False", "result": "clean site"}, "CRDF": {"detected": "False", "result": "clean site"}, "CSIS Security Group": {"detected": "False", "result": "unrated site"}, "Certego": {"detected": "False", "result": "clean site"}, "Chong Lua Dao": {"detected": "False", "result": "clean site"}, "Cluster25": {"detected": "False", "result": "unrated site"}, "Criminal IP": {"detected": "False", "result": "clean site"}, "CyRadar": {"detected": "False", "result": "clean site"}, "Cyan": {"detected": "False", "result": "unrated site"}, "Cyble": {"detected": "False", "result": "clean site"}, "DNS8": {"detected": "False", "result": "clean site"}, "Dr.Web": {"detected": "False", "result": "clean site"}, "ESET": {"detected": "False", "result": "clean site"}, "ESTsecurity": {"detected": "False", "result": "clean site"}, "EmergingThreats": {"detected": "False", "result": "clean site"}, "Emsisoft": {"detected": "False", "result": "clean site"}, "Ermes": {"detected": "False", "result": "unrated site"}, "Feodo Tracker": {"detected": "False", "result": "clean site"}, "Forcepoint ThreatSeeker": {"detected": "False", "result": "clean site"}, "Fortinet": {"detected": "False", "result": "clean site"}, "G-Data": {"detected": "False", "result": "clean site"}, "Google Safebrowsing": {"detected": "False", "result": "clean site"}, "GreenSnow": {"detected": "False", "result": "clean site"}, "Gridinsoft": {"detected": "False", "result": "unrated site"}, "Heimdal Security": {"detected": "False", "result": "clean site"}, "Hunt.io Intelligence": {"detected": "False", "result": "unrated site"}, "IPsum": {"detected": "False", "result": "clean site"}, "Juniper Networks": {"detected": "False", "result": "clean site"}, "K7AntiVirus": {"detected": "False", "result": "clean site"}, "Kaspersky": {"detected": "False", "result": "clean site"}, "Lionic": {"detected": "False", "result": "clean site"}, "Lumu": {"detected": "False", "result": "unrated site"}, "MalwarePatrol": {"detected": "False", "result": "clean site"}, "MalwareURL": {"detected": "False", "result": "unrated site"}, "Malwared": {"detected": "False", "result": "clean site"}, "Netcraft": {"detected": "False", "result": "unrated site"}, "OpenPhish": {"detected": "False", "result": "clean site"}, "PREBYTES": {"detected": "False", "result": "clean site"}, "PhishFort": {"detected": "False", "result": "unrated site"}, "PhishLabs": {"detected": "False", "result": "unrated site"}, "Phishing Database": {"detected": "False", "result": "clean site"}, "Phishtank": {"detected": "False", "result": "clean site"}, "PrecisionSec": {"detected": "False", "result": "unrated site"}, "Quick Heal": {"detected": "False", "result": "clean site"}, "Quttera": {"detected": "False", "result": "clean site"}, "Rising": {"detected": "False", "result": "clean site"}, "SCUMWARE.org": {"detected": "False", "result": "clean site"}, "SOCRadar": {"detected": "False", "result": "unrated site"}, "SafeToOpen": {"detected": "False", "result": "unrated site"}, "Sangfor": {"detected": "False", "result": "clean site"}, "Sansec eComscan": {"detected": "False", "result": "unrated site"}, "Scantitan": {"detected": "False", "result": "clean site"}, "Seclookup": {"detected": "False", "result": "clean site"}, "Snort IP sample list": {"detected": "False", "result": "clean site"}, "Sophos": {"detected": "False", "result": "clean site"}, "Spam404": {"detected": "False", "result": "clean site"}, "StopForumSpam": {"detected": "False", "result": "clean site"}, "Sucuri SiteCheck": {"detected": "False", "result": "clean site"}, "ThreatHive": {"detected": "False", "result": "clean site"}, "Threatsourcing": {"detected": "False", "result": "clean site"}, "Trustwave": {"detected": "False", "result": "clean site"}, "URLQuery": {"detected": "False", "result": "unrated site"}, "URLhaus": {"detected": "False", "result": "clean site"}, "Underworld": {"detected": "False", "result": "unrated site"}, "VIPRE": {"detected": "False", "result": "unrated site"}, "VX Vault": {"detected": "False", "result": "clean site"}, "Viettel Threat Intelligence": {"detected": "False", "result": "clean site"}, "ViriBack": {"detected": "False", "result": "clean site"}, "Webroot": {"detected": "False", "result": "clean site"}, "Xcitium Verdict Cloud": {"detected": "False", "result": "unrated site"}, "Yandex Safebrowsing": {"detail": "http://yandex.com/infected?l10n=en&url=https://kinokrad.film/466421-madame-web.html", "detected": "False", "result": "clean site"}, "ZeroCERT": {"detected": "False", "result": "clean site"}, "alphaMountain.ai": {"detected": "False", "result": "clean site"}, "benkow.cc": {"detected": "False", "result": "clean site"}, "desenmascara.me": {"detected": "False", "result": "clean site"}, "malwares.com URL checker": {"detected": "False", "result": "clean site"}, "securolytics": {"detected": "False", "result": "clean site"}}, "total": 94, "url": "https://kinokrad.film/466421-madame-web.html"}, "blacklist_checker": {"valid_response": "True", "message": "URL found in BlackListChecker database.", "status": "ok", "input_raw": "172.67.199.131", "input_type": "ip_address", "input_domain": "None", "ip_address": "172.67.199.131", "detections": 0, "blacklists": [{"id": "apews_l2", "name": "APEWS-L2", "detected": "False"}, {"id": "azorult_tracker", "name": "AZORult Tracker", "detected": "False"}, {"id": "anti_attacks", "name": "Anti-Attacks Blacklist", "detected": "False"}, {"id": "antispam_cleantalk", "name": "AntiSpam by CleanTalk", "detected": "False"}, {"id": "backscatterer", "name": "Backscatterer", "detected": "False"}, {"id": "barracuda", "name": "Barracuda", "detected": "False"}, {"id": "blocked_servers", "name": "Blocked Servers", "detected": "False"}, {"id": "blocklist_de", "name": "Blocklist.de", "detected": "False"}, {"id": "blocklist_net_ua", "name": "Blocklist.net.ua", "detected": "False"}, {"id": "botvrij", "name": "Botvrij", "detected": "False"}, {"id": "brute_force_blocker", "name": "Brute Force Blocker", "detected": "False"}, {"id": "ci_army_list", "name": "CI Army List", "detected": "False"}, {"id": "cspace_hostings", "name": "CSpace Hostings IP Blacklist", "detected": "False"}, {"id": "cruzit", "name": "CruzIT Blocklist", "detected": "False"}, {"id": "cybercrime_tracker", "name": "Cybercrime Tracker", "detected": "False"}, {"id": "darklist_de", "name": "Darklist.de", "detected": "False"}, {"id": "efnet_rbl", "name": "EFnet RBL", "detected": "False"}, {"id": "etnetera", "name": "Etnetera Blacklist", "detected": "False"}, {"id": "fspamlist", "name": "FSpamList", "detected": "False"}, {"id": "feodo_tracker", "name": "Feodo Tracker", "detected": "False"}, {"id": "gpf_dns", "name": "GPF DNS Block List", "detected": "False"}, {"id": "greensnow", "name": "GreenSnow Blocklist", "detected": "False"}, {"id": "honeydb", "name": "HoneyDB Blacklist", "detected": "False"}, {"id": "ibm_cobion", "name": "IBM Cobion", "detected": "False"}, {"id": "ip_spamlist", "name": "IPSpamList", "detected": "False"}, {"id": "ipsum", "name": "IPsum", "detected": "False"}, {"id": "isx_fr", "name": "ISX.fr DNSBL", "detected": "False"}, {"id": "interserver", "name": "InterServer IP List", "detected": "False"}, {"id": "james_brine", "name": "JamesBrine IP List", "detected": "False"}, {"id": "justspam", "name": "JustSpam", "detected": "False"}, {"id": "lapps", "name": "LAPPS Grid Blacklist", "detected": "False"}, {"id": "liquid_binary", "name": "Liquid Binary", "detected": "False"}, {"id": "m4lwhere", "name": "M4lwhere Intel", "detected": "False"}, {"id": "mirai_tracker", "name": "Mirai Tracker", "detected": "False"}, {"id": "myip_ms", "name": "Myip.ms Blacklist", "detected": "False"}, {"id": "noc_rub", "name": "NOC RUB DE", "detected": "False"}, {"id": "nubi", "name": "NUBI Bad IPs", "detected": "False"}, {"id": "nginx_bad_bot", "name": "Nginx Bad Bot Blocker", "detected": "False"}, {"id": "nordspam", "name": "NordSpam", "detected": "False"}, {"id": "openphish", "name": "OpenPhish", "detected": "False"}, {"id": "psbl", "name": "Passive Spam Block List", "detected": "False"}, {"id": "phishtank", "name": "PhishTank", "detected": "False"}, {"id": "plonkatronix", "name": "Plonkatronix", "detected": "False"}, {"id": "rjm_blocklist", "name": "RJM Blocklist", "detected": "False"}, {"id": "redstout", "name": "Redstout Threat IP List", "detected": "False"}, {"id": "s5h", "name": "S5h Blacklist", "detected": "False"}, {"id": "ssl_blacklist", "name": "SSL Blacklist", "detected": "False"}, {"id": "sblam", "name": "Sblam", "detected": "False"}, {"id": "spamhaus", "name": "Spamhaus", "detected": "False"}, {"id": "talos", "name": "Talos IP Blacklist", "detected": "False"}, {"id": "threat_crowd", "name": "Threat Crowd", "detected": "False"}, {"id": "threat_sourcing", "name": "Threat Sourcing", "detected": "False"}, {"id": "threatlog", "name": "ThreatLog", "detected": "False"}, {"id": "url_haus", "name": "URLhaus", "detected": "False"}, {"id": "ustc_ip_bl", "name": "USTC IP BL", "detected": "False"}, {"id": "vx_vault", "name": "VXVault", "detected": "False"}, {"id": "viriback_c2", "name": "ViriBack C2 Tracker", "detected": "False"}], "checks_remaining": 46}}]}
            response_data = get_visualizations_data()
            print('md', services_checks)
            response_data.update(
                {
                    "request": request,
                    "error_message": error_message,
                    "checked_url": checked_url,
                    "provided_url": url,
                    "scan_result": services_checks,
                    "scan_result_exist": scan_result_exist,
                }
            )
            response = templates.TemplateResponse(
                "index.html",
                response_data
            )
            return response


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=settings.SERVICE_HOST,
        port=int(settings.SERVICE_PORT)
    )
