from typing import Optional
from openg2p_fastapi_auth_models.schemas import UserProfile as BaseUserProfile


class UserProfile(BaseUserProfile):
    login_provider_id: Optional[int] = None
    user_id: Optional[str] = None
    provider_unique_id: str
    provider_unique_id_type: str
