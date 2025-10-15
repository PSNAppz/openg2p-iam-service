from datetime import datetime
from typing import Optional

from openg2p_fastapi_common.context import dbengine
from openg2p_fastapi_common.models import BaseORMModelWithId
from sqlalchemy import DateTime, ForeignKey, Integer, String, Enum as SQLEnum
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from openg2p_fastapi_auth_models.schemas import UserType


class UserLoginLog(BaseORMModelWithId):
    __tablename__ = "user_login_logs"

    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    login_provider_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("login_providers.id", ondelete="SET NULL"),
        nullable=True,
    )
    provider_unique_id_type: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )
    user_type: Mapped[Optional[str]] = mapped_column(
        SQLEnum(UserType, name="user_type_enum"),
        nullable=True,
    )
    login_time: Mapped[datetime] = mapped_column(DateTime(), default=datetime.utcnow)

    @classmethod
    async def create_login_record(
        cls,
        user_id: int,
        login_provider_id: int,
        provider_unique_id_type: str,
        user_type: str,
    ) -> Optional["UserLoginLog"]:
        """
        Create a login record for the user.
        """
        async_session_maker = async_sessionmaker(dbengine.get(), expire_on_commit=False)
        async with async_session_maker() as session:
            login = cls(
                user_id=user_id,
                login_provider_id=login_provider_id,
                provider_unique_id_type=provider_unique_id_type,
                user_type=user_type,
                login_time=datetime.utcnow(),
                active=True,
            )
            session.add(login)
            await session.commit()
            await session.refresh(login)
            return login
