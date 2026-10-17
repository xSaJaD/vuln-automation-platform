"""بيئة Alembic — تقرأ الرابط من إعدادات التطبيق وتستهدف Base.metadata."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from api.config import settings
from api.models import Base  # noqa: F401  يحمّل كل النماذج

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

_db_url = settings.db_url or "sqlite:///./dev.db"
config.set_main_option("sqlalchemy.url", _db_url)


def run_migrations_offline() -> None:
    context.configure(
        url=_db_url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
