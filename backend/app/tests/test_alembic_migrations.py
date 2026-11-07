from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text


def test_alembic_revision_graph_has_single_head():
    """Production deploys run `alembic upgrade head`, so multiple heads block rollout."""
    backend_dir = Path(__file__).resolve().parents[2]
    config = Config(str(backend_dir / "alembic.ini"))
    script = ScriptDirectory.from_config(config)
    heads = script.get_heads()

    assert len(heads) == 1, f"Expected a single Alembic head, got {heads}"


def test_alert_notification_receipts_upgrade_and_downgrade(tmp_path, monkeypatch):
    """Existing history survives the receipt migration without pretending it was delivered."""
    database_url = f"sqlite:///{tmp_path / 'alert-receipts.sqlite'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    backend_dir = Path(__file__).resolve().parents[2]
    config = Config(str(backend_dir / "alembic.ini"))
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alert_history (id INTEGER PRIMARY KEY, detail TEXT)"))
        connection.execute(text("INSERT INTO alert_history VALUES (1, 'Existing alert')"))

    command.stamp(config, "4b5c6d7e8f9a")
    command.upgrade(config, "head")
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT detail, last_notified_at, notified_severity FROM alert_history")
        ).one()
        assert tuple(row) == ("Existing alert", None, None)

    command.downgrade(config, "4b5c6d7e8f9a")
    assert {column["name"] for column in inspect(engine).get_columns("alert_history")} == {
        "id",
        "detail",
    }
    with engine.connect() as connection:
        assert (
            connection.execute(text("SELECT detail FROM alert_history")).scalar()
            == "Existing alert"
        )
    engine.dispose()
