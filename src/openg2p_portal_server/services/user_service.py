import logging
from typing import List, Dict, Any

from openg2p_fastapi_common.errors.http_exceptions import InternalServerError
from openg2p_fastapi_common.service import BaseService

from ..config import Settings
from ..context import user_fields_cache
from openg2p_fastapi_auth_models.models import LoginProvider
from ..models import User
from ..schemas import UserProfile
from ..utils.user_utils import create_user_process_gender, create_user_process_birthdate


_config = Settings.get_config(strict=False)
_logger = logging.getLogger(_config.logging_default_logger_name)


class UserService(BaseService):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    async def check_and_create_user(
        self, validation: dict, id_type_config: dict = None
    ) -> User:
        """
        Checks if a user exists based on provider_unique_id, creates if not.
        """
        _logger.info("Checking and creating user")
        if not (id_type_config and id_type_config.get("g2p_id_type")):
            _logger.error(
                "Invalid Auth Provider Configuration. ID Type not configured."
            )
            raise InternalServerError(
                message="Invalid Auth Provider Configuration. ID Type not configured."
            )

        _logger.debug(
            f"Mapping validation response with token_map: {id_type_config['token_map']}"
        )
        validation: Dict[str, Any] = LoginProvider.map_validation_response(
            validation, id_type_config["token_map"]
        )

        _logger.debug(
            f"Looking up user by provider_unique_id: {validation['provider_unique_id']}"
        )
        existing_user: User = await User.get_user_by_provider_unique_id(
            validation["provider_unique_id"]
        )
        if existing_user:
            _logger.info("User already exists - fetched successfully")
            return existing_user

        _logger.debug("User not found, creating new user")
        user_profile: UserProfile = UserProfile(
            name=validation.get("name", ""),
            provider_unique_id=validation["provider_unique_id"],
            provider_unique_id_type=id_type_config.get("g2p_id_type"),
            user_id=validation.get("user_id"),
            email=validation.get("email"),
            gender=create_user_process_gender(validation.get("gender")),
            birthdate=create_user_process_birthdate(
                validation.get("birthdate"), date_format=id_type_config["date_format"]
            ),
            phone_number=validation.get("phone"),
            picture=validation.get("picture"),
            user_type=id_type_config.get("user_type"),
            login_provider_id=id_type_config.get("auth_provider_id"),
        )

        user: User = await User.create_user(user_profile=user_profile)

        _logger.info("User created successfully")
        return user

    async def get_user_fields(self) -> List[str]:
        _logger.info("Fetching user fields")
        fields: List[str] = user_fields_cache.get()
        if fields:
            return fields

        _logger.debug("Fetching user fields from database")
        fields = await User.get_user_fields()
        user_fields_cache.set(fields)

        _logger.info("User fields fetched successfully")
        return fields
