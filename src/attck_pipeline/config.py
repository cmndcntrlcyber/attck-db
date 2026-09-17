from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LISZT_")

    mongo_uri: str = "mongodb://localhost:27017"
    db_name: str = "liszt"
    db_secure_name: str = "liszt_secure"

    s3_endpoint_url: str = "http://localhost:9000"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_region: str = "us-east-1"
    s3_bucket_bundles: str = "attck-bundles"
    s3_bucket_reports: str = "liszt-reports"
    s3_enable_object_lock: bool = False

    stix_data_repo: str = "mitre-attack/attack-stix-data"
    stix_data_branch: str = "master"

    custom_domain: str = "cmndcntrl-custom"
    custom_namespace_prefix: str = "x-cmndcntrl-custom-"

    retention_years: int = 7

    notion_token: str = ""
    notion_collection_id: str = "5c2aa5cc-1ca1-4742-bf5d-57d55fa8507d"

    description_change_severity: str = "low"

    github_token: str = ""
    watch_domains: list[str] = ["enterprise-attack", "mobile-attack", "ics-attack"]
    watch_interval_seconds: int = 3600

    api_host: str = "0.0.0.0"
    api_port: int = 8000
