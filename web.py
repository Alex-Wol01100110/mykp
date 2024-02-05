"""Web application."""
import secrets

from typing import List, Dict

import uvicorn
from pydantic import BaseModel

from fastapi import Depends, FastAPI, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi import Form

from loguru import logger

from utils.general_utils import ModelUtils
import settings


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
security = HTTPBasic()
templates = Jinja2Templates(directory="templates")


class URLConfiguration(BaseModel):
    """
    Summary:
        Set base model of the report configuration.
    """
    urls: List


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
        urls_obj: URLConfiguration,
        authenticated: str = Depends(validate_credentials)
    ) -> Dict:
        """
        Summary:
            Test URLs status - safe or malicious.

        Args:
            urls (ReportConfiguration): configurations of reports.
            authenticated (str, optional): Bool value,
            that show if authentication is successful.

        Returns:
            Dict: key - url, value - status of url - safe or malicious..
        """
        statuses = {True: "URL is Malicious", False: "URL is Safe"}
        if authenticated:
            checked_urls = {
                url: statuses.get(ModelUtils.test_url(url))
                for url in urls_obj.urls
            }
            return checked_urls

    @logger.catch
    @app.get("/", response_class=HTMLResponse)
    async def get_index(request: Request):
        """
        Summary:

        Args:
            request (Request): request instance.

        Returns:
            TemplateResponse
        """
        scheme_x = ['http', "https", "N/A"]
        scheme_y = [49500, 6303, 1133]
        domain_x = [
            '9a327404-a-62cb3a1a-s-sites.googlegroups.com',
            'installer.jdownloader.org',
            'liceulogoga.ro',
            'sites.google.com',
            'ak.imgfarm.com'
        ]
        domain_y = [283, 1013, 1064, 1243, 2760]
        top_level_domain_x = ['ru', 'br', 'org', 'net', 'com']
        top_level_domain_y = [1320, 1320, 2760, 3291, 30952]
        general_x = ['safe', 'malicious']
        general_y = [991638, 56936]
        response = templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "scheme_x": scheme_x,
                "scheme_y": scheme_y,
                "scheme_title": "Top schemes",
                "domain_x": domain_x,
                "domain_y": domain_y,
                "domain_title": "Top Domains",
                "top_level_domain_x": top_level_domain_x,
                "top_level_domain_y": top_level_domain_y,
                "top_level_domain_title": "Top top-level domains",
                "general_x": general_x,
                "general_y": general_y,
                "general_title": "Safe vs Malicious URLs"
            }
        )
        return response

    @logger.catch
    @app.post("/", response_class=HTMLResponse)
    async def post_index(
        request: Request,
        url: str = Form(...),
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
            scheme_x = ['http', "https", "N/A"]
            scheme_y = [49500, 6303, 1133]
            domain_x = [
                '9a327404-a-62cb3a1a-s-sites.googlegroups.com',
                'installer.jdownloader.org',
                'liceulogoga.ro',
                'sites.google.com',
                'ak.imgfarm.com'
            ]
            domain_y = [283, 1013, 1064, 1243, 2760]
            top_level_domain_x = ['ru', 'br', 'org', 'net', 'com']
            top_level_domain_y = [1320, 1320, 2760, 3291, 30952]
            general_x = ['safe', 'malicious']
            general_y = [991638, 56936]
            checked_url = statuses.get(ModelUtils.test_url(url))
            response = templates.TemplateResponse(
                "index.html",
                {
                    "request": request, 
                    "checked_url": checked_url,
                    "scheme_x": scheme_x,
                    "scheme_y": scheme_y,
                    "scheme_title": "Scheme Pie Chart",
                    "domain_x": domain_x,
                    "domain_y": domain_y,
                    "domain_title": "Top Domains",
                    "top_level_domain_x": top_level_domain_x,
                    "top_level_domain_y": top_level_domain_y,
                    "top_level_domain_title": "Top level domains",
                    "general_x": general_x,
                    "general_y": general_y,
                    "general_title": "Safe vs Malicious URLs"
                }
            )
            return response


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=settings.SERVICE_HOST,
        port=int(settings.SERVICE_PORT)
    )
