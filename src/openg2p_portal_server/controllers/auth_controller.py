import base64
import hashlib
import logging
import secrets
import urllib.parse
from typing import Any, Dict, Optional, Annotated
from datetime import datetime, timedelta, timezone

import httpx
import orjson
from fastapi import Depends, HTTPException, Response, status, Request
from fastapi.datastructures import QueryParams
from fastapi.responses import RedirectResponse
from jose import jwt
from openg2p_fastapi_common.controller import BaseController
from openg2p_fastapi_common.errors.http_exceptions import (
    InternalServerError,
    UnauthorizedError,
)
from openg2p_fastapi_auth.dependencies import JwtBearerAuth
from openg2p_fastapi_auth.auth.factory import AuthFactory
from openg2p_fastapi_auth_models.schemas import (
    LoginProviderHttpResponse,
    LoginProviderResponse,
    LoginProviderTypes,
    UserProfile,
    AuthCredentials,
    OauthClientAssertionType,
    OauthProviderParameters,
)
from openg2p_fastapi_auth_models.models import LoginProvider
from ..models import UserLoginLog, User
from ..config import Settings


_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class AuthController(BaseController):
    """
    Step-1 --> UI calls API - get_login_providers (to get a list of all available login providers) - ESignet & Keycloak
    Step-2 --> UI lists these options
    Step-3 --> User chooses one of the Login Providers
    Step-4 --> UI calls the "get_login_provider_redirect_url" -- for the chosen Login Provider, UI also provides the portal-server callback URL for this API call
    Step-5 --> User authenticates himself in the chosen login provider
    Step-6 --> Login Provider provides a temporary token
    Step-7 --> Control returns back to the UI, the UI sends this temporary token to the portal-server Callback URL specified (/callback)
    Step-8 --> portal-server now calls the Login Provider with Client ID and Secret to exchange the temporary token for the Access Token & Refresh Token
    Step-9 --> Login Provider issues the Access & Refresh Token
    Step-10 --> portal-server - registers the token with the request cookies
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.router.prefix += "/auth"
        self.router.tags += ["auth"]

        self.router.add_api_route(
            "/get_user_profile",
            self.get_user_profile,
            responses={200: {"model": UserProfile}},
            methods=["GET"],
        )
        self.router.add_api_route(
            "/logout",
            self.logout,
            methods=["POST"],
        )
        self.router.add_api_route(
            "/get_login_providers",
            self.get_login_providers,
            responses={200: {"model": LoginProviderHttpResponse}},
            methods=["GET"],
        )
        self.router.add_api_route(
            "/get_login_provider_redirect/{id}",
            self.get_login_provider_redirect,
            methods=["GET"],
        )
        self.router.add_api_route(
            "/callback",
            self.oauth_callback,
            methods=["GET"],
        )

    async def get_user_profile(
        self,
        auth: Annotated[AuthCredentials, Depends(AuthFactory())],
        online: bool = True,
    ):
        """
        Get Profile Data of the authenticated user/entity.
        This can also be used to check whether or not the Authentication is present and valid.
        - Authentication required.
        - If online is true, the server will try to userinfo from original Authorization Server.
          Else it will return the information present in ID Token and Access token.
        """
        if online:
            provider = await self.get_login_provider_db_by_iss(auth.iss)
            if provider:
                if provider.type == LoginProviderTypes.oauth2_auth_code:
                    return UserProfile.model_validate(
                        await self.get_oauth_validation_data(
                            auth, iss=auth.iss, provider=provider, combine=True
                        )
                    )
                else:
                    raise NotImplementedError()
        return UserProfile.model_validate(auth.model_dump())

    async def logout(self, response: Response):
        """
        Perform Logout. This clears the Access Tokens and ID Tokens from cookies.
        - Authentication not mandatory.
        """
        response.delete_cookie("X-Access-Token")
        response.delete_cookie("X-ID-Token")

    async def get_login_providers(self):
        """
        Get available Login Providers List. Can also be used to display login providers on UI.
        Use getLoginProviderRedirect API to redirect to this Login Provider to perform login.
        """
        login_providers = await self.get_login_providers_db()
        return LoginProviderHttpResponse(
            loginProviders=[
                LoginProviderResponse(
                    id=lp.id,
                    name=lp.name,
                    type=lp.flow,
                    displayName=lp.body,
                    displayIconUrl=lp.image_icon_url,
                )
                for lp in login_providers
            ],
        )

    async def get_login_provider_redirect(self, id: int, redirect_uri: str = "/"):
        """
        Redirect URL to redirect to the Login Provider's Authorization URL
        based on the id of login provider given.
        """
        login_provider = None
        try:
            login_provider = await self.get_login_provider_db_by_id(id)
        except Exception as e:
            _logger.exception("Login Provider fetching: Invalid Id")
            # Instead of returning None, re-raise the exception to be handled by FastAPI
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Login Provider ID Not Found",
            ) from e

        if not login_provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Login Provider ID Not Found",
            )

        if login_provider.flow == LoginProviderTypes.oauth2_auth_code.value:
            # auth_parameters = OauthProviderParameters.model_validate(
            #     login_provider.__dict__.copy()
            # )
            provider_data = {
                "auth_endpoint": login_provider.auth_endpoint,
                "token_endpoint": login_provider.token_endpoint,
                "validation_endpoint": login_provider.validation_endpoint,
                "jwks_uri": login_provider.jwks_uri,
                "client_id": login_provider.client_id,
                "client_secret": login_provider.client_secret,
                "g2p_portal_oauth_callback_url": login_provider.g2p_portal_oauth_callback_url,
                "scope": login_provider.scope or "openid profile email",
                "enable_pkce": login_provider.enable_pkce,
                "code_verifier": login_provider.code_verifier or "",
                "extra_authorize_params": orjson.loads(login_provider.extra_authorize_params or "{}"),
                # Set defaults for missing fields
                "response_type": "code",
                "code_challenge": "",
                "code_challenge_method": "S256",
            }
            auth_parameters = OauthProviderParameters.model_validate(provider_data)
            authorize_query_params = {
                "client_id": auth_parameters.client_id,
                "response_type": auth_parameters.response_type,
                "redirect_uri": auth_parameters.g2p_portal_oauth_callback_url,
                "scope": auth_parameters.scope,
                "nonce": secrets.token_urlsafe(),
                "state": orjson.dumps(
                    {
                        "p": login_provider.id,
                        "r": redirect_uri,
                    }
                ).decode(),
            }
            if auth_parameters.enable_pkce:
                await self.pkce_get_or_generate_code_verifier(login_provider)
                self.pkce_update_code_challenge(auth_parameters)
                authorize_query_params.update(
                    {
                        "code_challenge": auth_parameters.code_challenge,
                        "code_challenge_method": auth_parameters.code_challenge_method,
                    }
                )

            authorize_query_params.update(auth_parameters.extra_authorize_params)
            return RedirectResponse(
                f"{auth_parameters.auth_endpoint}?{urllib.parse.urlencode(authorize_query_params)}"
            )
        else:
            raise NotImplementedError()

    async def pkce_get_or_generate_code_verifier(
        self, login_provider: LoginProvider
    ) -> str:
        code_verifier = login_provider.code_verifier
        if not code_verifier:
            code_verifier = secrets.token_urlsafe(32)
            login_provider.code_verifier = code_verifier
            await login_provider.update_to_db()
        return code_verifier

    def pkce_update_code_challenge(self, auth_params: OauthProviderParameters):
        if auth_params.code_challenge_method.lower() == "s256":
            auth_params.code_challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(auth_params.code_verifier.encode("ascii")).digest()
                )
                .rstrip(b"=")
                .decode()
            )

    async def get_login_providers_db(self) -> list[LoginProvider]:
        return await LoginProvider.get_all()

    async def get_login_provider_db_by_id(self, id: int) -> LoginProvider:
        return await LoginProvider.get_by_id(id)

    async def get_login_provider_db_by_iss(self, iss: str) -> LoginProvider:
        if _config.login_providers_list:
            lp_fields = LoginProvider.__mapper__.columns.keys()
            for lp in _config.login_providers_list:
                if iss == lp.get("iss"):
                    return LoginProvider(
                        **{
                            lp_key: lp_val
                            for lp_key, lp_val in lp.items()
                            if lp_key in lp_fields
                        }
                    )
            return None
        if await LoginProvider.table_exists_cached():
            return await LoginProvider.get_login_provider_from_iss(iss)
        return None

    async def get_oauth_validation_data(
        self,
        auth: str | AuthCredentials,
        id_token: str = None,
        iss: str = None,
        provider: LoginProvider = None,
        combine=True,
    ) -> dict:
        access_token = auth.credentials if isinstance(auth, AuthCredentials) else auth
        if not provider:
            if not iss:
                iss = (
                    jwt.get_unverified_claims(access_token)["iss"]
                    if isinstance(auth, str)
                    else auth.iss
                )
            provider = await self.get_login_provider_db_by_iss(iss)
        # TODO: Check if provider is None
        auth_params = OauthProviderParameters.model_validate(
            provider.authorization_parameters
        )
        try:
            response = httpx.get(
                auth_params.validate_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            if response.headers["content-type"].startswith("application/json"):
                res = response.json()
            elif response.headers["content-type"].startswith("application/jwt"):
                # jwks_cache.get().get(auth.iss),
                # TODO: Skipping this jwt validation. Some errors.
                res = jwt.get_unverified_claims(response.content)
            if combine:
                return JwtBearerAuth.combine_tokens(access_token, id_token, res)
            else:
                return res
        except Exception as e:
            _logger.exception("Error fetching user profile.")
            raise InternalServerError(
                "G2P-AUT-502",
                f"Error fetching userinfo. {repr(e)}",
            ) from e

    async def oauth_callback(self, request: Request):
        """
        Oauth2 Redirect Url. Auth Server will redirect to this URL after the Authentication is successful.

        Internal Errors:
        - Code: G2P-AUT-401. HTTP: 401. Message: Login Provider Id not received.
        """
        state = orjson.loads(request.query_params.get("state", "{}"))
        login_provider_id = state.get("p", None)
        if not login_provider_id:
            raise UnauthorizedError("G2P-AUT-401", "Login Provider Id not received")

        login_provider = await self.get_login_provider_db_by_id(
            login_provider_id
        )

        res = await self.get_tokens(login_provider, request.query_params)

        config_dict = _config.model_dump()
        access_token: str = res["access_token"]
        id_token: str = res["id_token"]
        expires_in = None
        if config_dict.get("auth_cookie_set_expires", False):
            expires_in = res.get("expires_in", None)
            if expires_in:
                expires_in = datetime.now(tz=timezone.utc) + timedelta(
                    seconds=expires_in
                )
        # Check and Create User If Not Exists
        userinfo_dict = await self.get_oauth_validation_data(
            auth=access_token,
            id_token=id_token,
            provider=login_provider,
        )

        id_type_config: Optional[
            Dict[str, Any]
        ] = await LoginProvider.get_auth_id_type_config(id=login_provider_id)

        user: User = await self.user_service.check_and_create_user(
            userinfo_dict, id_type_config=id_type_config
        )
        await UserLoginLog.create_login_record(
            user_id=user.id,
            login_provider_id=id_type_config.get("login_provider_id"),
            provider_unique_id_type=id_type_config.get("g2p_id_type"),
            user_type=user.user_type,
        )

        response = RedirectResponse(state.get("r", "/"))
        response.set_cookie(
            "X-Access-Token",
            access_token,
            max_age=config_dict.get("auth_cookie_max_age", None),
            expires=expires_in,
            path=config_dict.get("auth_cookie_path", "/"),
            httponly=config_dict.get("auth_cookie_httponly", True),
            secure=config_dict.get("auth_cookie_secure", True),
        )
        response.set_cookie(
            "X-ID-Token",
            id_token,
            max_age=config_dict.get("auth_cookie_max_age", None),
            expires=expires_in,
            path=config_dict.get("auth_cookie_path", "/"),
            httponly=config_dict.get("auth_cookie_httponly", True),
            secure=config_dict.get("auth_cookie_secure", True),
        )

        return response

    async def get_tokens(
        self, login_provider: LoginProvider, query_params: QueryParams, **kw
    ):
        if login_provider.flow == LoginProviderTypes.oauth2_auth_code.value:
            # auth_parameters = OauthProviderParameters.model_validate(
            #     login_provider.auth_parameters
            # )
            provider_data = {
                "auth_endpoint": login_provider.auth_endpoint,
                "token_endpoint": login_provider.token_endpoint,
                "validation_endpoint": login_provider.validation_endpoint,
                "jwks_uri": login_provider.jwks_uri,
                "client_id": login_provider.client_id,
                "client_secret": login_provider.client_secret,
                "g2p_portal_oauth_callback_url": login_provider.g2p_portal_oauth_callback_url,
                "scope": login_provider.scope or "openid profile email",
                "enable_pkce": login_provider.enable_pkce,
                "code_verifier": login_provider.code_verifier or "",
                "extra_authorize_params": orjson.loads(login_provider.extra_authorize_params or "{}"),
                # Set defaults for missing fields
                "response_type": "code",
                "code_challenge": "",
                "code_challenge_method": "S256",
            }
            auth_parameters = OauthProviderParameters.model_validate(provider_data)
            token_request_data = {
                "client_id": auth_parameters.client_id,
                "grant_type": "authorization_code",
                "redirect_uri": auth_parameters.g2p_portal_oauth_callback_url,
                "code": query_params.get("code"),
            }
            if auth_parameters.enable_pkce:
                token_request_data["code_verifier"] = auth_parameters.code_verifier

            token_auth = None
            if auth_parameters.client_assertion_type.name.startswith("private_key_jwt"):
                await self.update_client_assertion(
                    auth_parameters, token_request_data, **kw
                )
            elif (
                auth_parameters.client_assertion_type
                == OauthClientAssertionType.client_secret_basic
            ):
                token_auth = (auth_parameters.client_id, auth_parameters.client_secret)
            elif (
                auth_parameters.client_assertion_type
                == OauthClientAssertionType.client_secret
            ):
                token_request_data["client_secret"] = auth_parameters.client_secret
            try:
                res = httpx.post(
                    auth_parameters.token_endpoint,
                    auth=token_auth,
                    data=orjson.loads(orjson.dumps(token_request_data)),
                )
                res.raise_for_status()
                res = res.json()
                return res
            except Exception as e:
                _logger.exception(
                    "Error while fetching token from token endpoint, %s",
                    auth_parameters.token_endpoint,
                )
                raise UnauthorizedError(
                    message="Unauthorized. Failed to get token from Oauth Server"
                ) from e
        else:
            raise NotImplementedError()

    async def update_client_assertion(
        self, auth_parameters: OauthProviderParameters, token_request_data: dict, **kw
    ):
        if (
            auth_parameters.client_assertion_type
            == OauthClientAssertionType.private_key_jwt
            or auth_parameters.client_assertion_type
            == OauthClientAssertionType.private_key_jwt_legacy
        ):
            iat = datetime.now(tz=timezone.utc).replace(tzinfo=None)
            exp = iat + timedelta(hours=1)
            client_assertion_type = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            client_assertion = jwt.encode(
                {
                    "iss": auth_parameters.client_id,
                    "sub": auth_parameters.client_id,
                    "aud": auth_parameters.client_assertion_jwt_aud
                    or auth_parameters.token_endpoint,
                    "iat": int(iat.timestamp()),
                    "exp": int(exp.timestamp()),
                },
                auth_parameters.client_assertion_jwk,
                algorithm="RS256",
            )
        elif (
            auth_parameters.client_assertion_type
            == OauthClientAssertionType.private_key_jwt_keymanager
        ):
            client_assertion_type = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            client_assertion = await self.generate_client_assertion_keymanager(
                auth_parameters, **kw
            )
        else:
            raise NotImplementedError()
        token_request_data.update(
            {
                "client_assertion_type": client_assertion_type,
                "client_assertion": client_assertion,
            }
        )

    async def generate_client_assertion_keymanager(
        self, auth_parameters: OauthProviderParameters, **kw
    ):
        app_id_ref_id = auth_parameters.client_assertion_jwk_keymanager
        if ":" in app_id_ref_id:
            km_app_id = auth_parameters.client_assertion_jwk_keymanager.split(":")[
                0
            ].strip()
            km_ref_id = auth_parameters.client_assertion_jwk_keymanager.split(":")[
                1
            ].strip()
        else:
            km_app_id = app_id_ref_id
            km_ref_id = ""
        iat = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        exp = iat + timedelta(hours=1)
        return await self.keymanager_helper.create_jwt_token(
            {
                "iss": auth_parameters.client_id,
                "sub": auth_parameters.client_id,
                "aud": auth_parameters.client_assertion_jwt_aud
                or auth_parameters.token_endpoint,
                "iat": int(iat.timestamp()),
                "exp": int(exp.timestamp()),
            },
            km_app_id=km_app_id,
            km_ref_id=km_ref_id,
            **kw,
        )
