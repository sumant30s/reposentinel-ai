from alembic import context
from app.core.config import get_settings
from app.models.database import Base, make_engine

settings = get_settings()
settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
if context.is_offline_mode():
    context.configure(url=settings.database_url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    with make_engine(settings.database_url).connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=Base.metadata,
            compare_type=True,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()
