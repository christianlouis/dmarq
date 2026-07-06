import time
from typing import List, Dict, Optional

DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE = 500

class MockQuery:
    def __init__(self):
        pass
    def join(self, *args, **kwargs):
        return self
    def filter(self, *args, **kwargs):
        return self
    def all(self):
        return []

class MockDB:
    def __init__(self):
        self.query_count = 0
    def query(self, *args, **kwargs):
        self.query_count += 1
        return MockQuery()

class Domain:
    name = "name"
    dkim_selectors = "selectors"
    id = "id"

def _normalize_domain_selectors(selectors: List[str]) -> List[str]:
    return selectors

def original_get_domain_selectors(db, domain_names: List[str]):
    if not domain_names:
        return {}

    unique_names = list(dict.fromkeys(domain_names))
    selectors_by_domain: Dict[str, List[str]] = {}
    for index in range(0, len(unique_names), DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE):
        chunk = unique_names[index : index + DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE]
        rows = db.query(Domain.name, Domain.dkim_selectors).filter(Domain.name == chunk).all()
        for name, selectors in rows:
            selectors_by_domain[name] = _normalize_domain_selectors((selectors or "").split(","))
    return selectors_by_domain

def optimized_get_domain_selectors(db, domain_names: List[str]):
    if not domain_names:
        return {}

    unique_names = list(dict.fromkeys(domain_names))
    selectors_by_domain: Dict[str, List[str]] = {}

    rows = db.query(Domain.name, Domain.dkim_selectors).filter(Domain.name == unique_names).all()
    for name, selectors in rows:
        selectors_by_domain[name] = _normalize_domain_selectors((selectors or "").split(","))
    return selectors_by_domain

if __name__ == "__main__":
    domains = [f"domain{i}.com" for i in range(10000)]

    db1 = MockDB()
    start1 = time.time()
    original_get_domain_selectors(db1, domains)
    end1 = time.time()

    db2 = MockDB()
    start2 = time.time()
    optimized_get_domain_selectors(db2, domains)
    end2 = time.time()

    print(f"Original: {db1.query_count} queries in {end1 - start1:.6f} seconds")
    print(f"Optimized: {db2.query_count} queries in {end2 - start2:.6f} seconds")
    print(f"Improvement: {(end1-start1) / (end2-start2 + 1e-9):.2f}x faster, {(db1.query_count - db2.query_count)} fewer database queries.")
