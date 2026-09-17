from dagster import Definitions, load_assets_from_modules

from attck_pipeline.orchestration.assets import diff, impact, ingest, overlay, reports
from attck_pipeline.orchestration.resources import MongoResource, S3Resource, SettingsResource
from attck_pipeline.orchestration.sensors import github_release_sensor

defs = Definitions(
    assets=load_assets_from_modules([ingest, diff, impact, overlay, reports]),
    resources={
        "settings_res": SettingsResource(),
        "mongo": MongoResource(),
        "s3_res": S3Resource(),
    },
    sensors=[github_release_sensor],
)
