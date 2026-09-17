from __future__ import annotations

from pymongo.database import Database


class LineageResolver:
    def __init__(self, db: Database):
        self.db = db

    def resolve_to_active(self, stix_id: str, release_id: str, max_depth: int = 10) -> dict:
        try:
            return self._graphlookup(stix_id, release_id, max_depth)
        except Exception:
            return self._iterative_walk(stix_id, release_id, max_depth)

    def _graphlookup(self, stix_id: str, release_id: str, max_depth: int) -> dict:
        pipeline = [
            {"$match": {
                "release_id": release_id,
                "kind": "revoked_by",
                "from.stix_id": stix_id,
            }},
            {"$graphLookup": {
                "from": "identity_edges",
                "startWith": "$to.stix_id",
                "connectFromField": "to.stix_id",
                "connectToField": "from.stix_id",
                "as": "chain",
                "maxDepth": max_depth,
                "depthField": "depth",
                "restrictSearchWithMatch": {
                    "release_id": release_id,
                    "kind": "revoked_by",
                },
            }},
        ]
        results = list(self.db.identity_edges.aggregate(pipeline))
        if not results:
            return {"stix_id": stix_id, "chain": [], "terminal": None, "is_active": None}

        row = results[0]
        chain_edges = sorted(row.get("chain", []), key=lambda e: e.get("depth", 0))

        if chain_edges:
            terminal_stix_id = chain_edges[-1]["to"]["stix_id"]
        else:
            terminal_stix_id = row["to"]["stix_id"]

        terminal_member = self.db.release_members.find_one({
            "release_id": release_id,
            "stix_id": terminal_stix_id,
        })
        is_active = terminal_member["state"] == "active" if terminal_member else None

        full_chain = [{"from": row["from"]["stix_id"], "to": row["to"]["stix_id"], "depth": 0}]
        for edge in chain_edges:
            full_chain.append({
                "from": edge["from"]["stix_id"],
                "to": edge["to"]["stix_id"],
                "depth": edge["depth"] + 1,
            })

        return {
            "stix_id": stix_id,
            "chain": full_chain,
            "terminal": terminal_stix_id,
            "is_active": is_active,
        }

    def _iterative_walk(self, stix_id: str, release_id: str, max_depth: int) -> dict:
        chain = []
        current = stix_id
        visited = set()

        for depth in range(max_depth):
            if current in visited:
                break
            visited.add(current)

            edge = self.db.identity_edges.find_one({
                "release_id": release_id,
                "kind": "revoked_by",
                "from.stix_id": current,
            })
            if not edge:
                break

            next_id = edge["to"]["stix_id"]
            chain.append({"from": current, "to": next_id, "depth": depth})
            current = next_id

        terminal = current if current != stix_id else None
        is_active = None
        if terminal:
            member = self.db.release_members.find_one({
                "release_id": release_id,
                "stix_id": terminal,
            })
            is_active = member["state"] == "active" if member else None

        return {
            "stix_id": stix_id,
            "chain": chain,
            "terminal": terminal,
            "is_active": is_active,
        }
