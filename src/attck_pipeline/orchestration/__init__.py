try:
    import dagster  # noqa: F401
    DAGSTER_AVAILABLE = True
except ImportError:
    DAGSTER_AVAILABLE = False
