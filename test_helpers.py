import sys
import os
import json

from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath('backend'))

# Mock FastAPI
import sys
sys.modules['fastapi'] = MagicMock()
sys.modules['fastapi.routing'] = MagicMock()
sys.modules['fastapi.security'] = MagicMock()
sys.modules['fastapi.responses'] = MagicMock()
sys.modules['app.core.config'] = MagicMock()
sys.modules['app.models.domain'] = MagicMock()
sys.modules['app.models.report'] = MagicMock()
sys.modules['app.db.session'] = MagicMock()
sys.modules['pydantic'] = MagicMock()
sys.modules['sqlalchemy'] = MagicMock()
sys.modules['sqlalchemy.orm'] = MagicMock()
sys.modules['sqlalchemy.exc'] = MagicMock()

from app.api.api_v1.endpoints.domains import _get_domain_selectors_map_from_db, _get_report_selectors_map_from_db

class MockDB:
    def query(self, *args, **kwargs):
        return MockQuery()

class MockQuery:
    def join(self, *args, **kwargs):
        return self
    def filter(self, *args, **kwargs):
        return self
    def all(self):
        return [("example.com", "sel1,sel2"), ("test.com", "sel3")]

def test_get_domain_selectors_map_from_db():
    db = MockDB()
    result = _get_domain_selectors_map_from_db(db, ["example.com", "test.com"])
    assert result == {"example.com": ["sel1", "sel2"], "test.com": ["sel3"]}

class MockReportQuery:
    def join(self, *args, **kwargs):
        return self
    def filter(self, *args, **kwargs):
        return self
    def all(self):
        return [("example.com", json.dumps([{"selector": "sel4"}, {"selector": "sel5"}]))]

class MockReportDB:
    def query(self, *args, **kwargs):
        return MockReportQuery()

def test_get_report_selectors_map_from_db():
    db = MockReportDB()
    result = _get_report_selectors_map_from_db(db, ["example.com"])
    assert result == {"example.com": ["sel4", "sel5"]}

test_get_domain_selectors_map_from_db()
test_get_report_selectors_map_from_db()
print("Tests passed!")
