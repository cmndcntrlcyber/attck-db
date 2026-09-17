from __future__ import annotations

import json

from dagster import RunRequest, SensorEvaluationContext, sensor

from attck_pipeline.orchestration.resources import MongoResource, SettingsResource


@sensor(minimum_interval_seconds=3600)
def github_release_sensor(
    context: SensorEvaluationContext,
    settings_res: SettingsResource,
    mongo: MongoResource,
):
    """Poll GitHub for new ATT&CK releases and trigger ingest runs."""
    from attck_pipeline.sources.github_watch import GitHubReleaseWatcher

    settings = settings_res.get_settings()
    watcher = GitHubReleaseWatcher(settings)

    cursor = json.loads(context.cursor) if context.cursor else {"seen_tags": []}
    seen_tags = set(cursor.get("seen_tags", []))

    new_releases = watcher.discover_new_versions(mongo.db)

    for release in sorted(new_releases, key=lambda r: r.version):
        tag_key = f"{release.domain}@{release.version}"
        if tag_key in seen_tags:
            continue

        seen_tags.add(tag_key)
        yield RunRequest(
            run_key=tag_key,
            run_config={
                "ops": {
                    "stix_bundle": {"config": {"domain": release.domain, "version": release.version}},
                }
            },
        )
        context.log.info(f"Triggered ingest for {tag_key}")

    context.update_cursor(json.dumps({"seen_tags": sorted(seen_tags)}))
