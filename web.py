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
from utils.custom_models import URLsSettings, URLSettings
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
    @app.post("/test_urls/", tags=["Test URLs"], response_model=Dict[str, str])
    async def test_urls(
        urls: tuple[AnyUrl, ...],
        authenticated: str = Depends(validate_credentials)
    ) -> Dict[str, str]:
        """
        Summary:
            Test URLs status - safe or malicious.
        
        Body:
            list of valid urls.

        Returns:
            Dict[str, str]: key - url,
            value - status of url - Safe or Malicious.
        """
        statuses = {True: "Malicious", False: "Safe"}
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
                if additional_checks:
                    services_checks = perform_services_checks(
                        URLsSettings(urls=(URLSettings(url=url),))
                    )
                    services_checks = services_checks.model_dump()
            response_data = get_visualizations_data()
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
