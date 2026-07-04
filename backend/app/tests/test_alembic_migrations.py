from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_alembic_revision_graph_has_single_head():
    """Production deploys run `alembic upgrade head`, so multiple heads block rollout."""
    backend_dir = Path(__file__).resolve().parents[2]
    config = Config(str(backend_dir / "alembic.ini"))
    script = ScriptDirectory.from_config(config)

    assert script.get_heads() == ["d9e0f1a2b3c4"]
