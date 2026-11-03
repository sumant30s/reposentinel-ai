from app.schemas.contracts import FindingData


def prioritize(
    item: FindingData, exposure: str = "internal", critical_asset: bool = False
) -> FindingData:
    base = {"low": 20, "medium": 45, "high": 70, "critical": 90}[item.severity]
    adjustment = {"low": -10, "medium": 0, "high": 5}[item.confidence]
    score = max(
        0,
        min(
            100,
            base
            + adjustment
            + (10 if exposure == "internet" else 0)
            + (10 if critical_asset else 0),
        ),
    )
    item.priority_score = score
    item.priority = (
        "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"
    )
    item.priority_reason = f"Base {base} from severity; confidence {adjustment:+}; internet exposure {10 if exposure == 'internet' else 0:+}; critical asset {10 if critical_asset else 0:+}. Heuristic score, not CVSS or exploitation probability."
    return item


def deduplicate(items: list[FindingData]) -> list[FindingData]:
    unique: dict[str, FindingData] = {}
    for item in items:
        item.identify()
        if item.fingerprint in unique:
            old = unique[item.fingerprint]
            old.engines = sorted(set(old.engines + item.engines))
        else:
            unique[item.fingerprint] = item
    return list(unique.values())
