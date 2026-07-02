from __future__ import annotations

from scytaledroid.Database.db_utils import dynamic_service_context as catalog
from scytaledroid.DynamicAnalysis import service_context


def test_backfill_dynamic_service_context_help_is_safe(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/backfill_dynamic_service_context.py")


def test_apply_dynamic_service_context_migration_records_schema_and_seeds(monkeypatch) -> None:
    ddl_statements: list[str] = []
    appended_versions: list[str] = []
    migration_rows: list[dict[str, object]] = []
    seeded_services: list[tuple[object, ...]] = []
    seeded_maps: list[tuple[object, ...]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if "FROM schema_migrations" in sql and "migration_entry_id" in sql:
            return None
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.9-dynamic-domain-context-collation-hotfix"}
        if query_name == f"schema_migrations.apply.{catalog.MIGRATION_ID}":
            ddl_statements.append(sql.strip())
            return None
        if query_name == "dynamic_service_context.upsert_service":
            seeded_services.append(tuple(params))
            return None
        if query_name == "dynamic_service_context.upsert_domain_map":
            seeded_maps.append(tuple(params))
            return None
        if query_name == "schema_migrations.append_schema_version":
            appended_versions.append(str(params[0]))
            return None
        if query_name == "dynamic_service_context.service_count":
            return {"n": len(seeded_services)}
        if query_name == "dynamic_service_context.domain_map_count":
            return {"n": len(seeded_maps)}
        if query_name == "dynamic_service_context.load_services":
            return [
                {
                    "service_key": row[0],
                    "display_name": row[1],
                    "owner_name": row[2],
                    "owner_class": row[3],
                    "service_category": row[4],
                    "primary_use_case": row[5],
                    "documentation_url": row[6],
                    "privacy_policy_url": row[7],
                    "source_label": row[8],
                    "source_url": row[9],
                    "confidence": row[10],
                    "notes": row[11],
                }
                for row in seeded_services
            ]
        if query_name == "dynamic_service_context.load_domain_maps":
            return [
                {
                    "service_key": row[0],
                    "package_name_scope": row[1],
                    "domain_pattern": row[2],
                    "match_type": row[3],
                    "role_class": row[4],
                    "source_label": row[5],
                    "source_url": row[6],
                    "confidence": row[7],
                    "notes": row[8],
                }
                for row in seeded_maps
            ]
        if query_name == "schema_migrations.insert":
            migration_rows.append(
                {
                    "migration_id": params[0],
                    "schema_version_before": params[4],
                    "schema_version_after": params[5],
                    "status": params[9],
                    "receipt_path": params[11],
                }
            )
            return None
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr(
        catalog,
        "write_dynamic_service_context_receipt_bundle",
        lambda payload, _output_dir: {  # noqa: ARG005
            "json": "/tmp/dynamic-service-context.json",
            "services_csv": "/tmp/dynamic-service-context-services.csv",
            "domain_maps_csv": "/tmp/dynamic-service-context-domain-maps.csv",
        },
    )

    payload = catalog.apply_dynamic_service_context_migration(fake_run_sql)

    assert len(ddl_statements) == 2
    assert appended_versions == ["0.3.10-dynamic-service-context"]
    assert payload["services_seeded"] == len(service_context.default_service_catalog_seed_rows())
    assert payload["domain_maps_seeded"] == len(service_context.default_service_domain_map_seed_rows())
    assert len(seeded_services) >= 8
    assert len(seeded_maps) >= 10
    assert migration_rows == [
        {
            "migration_id": catalog.MIGRATION_ID,
            "schema_version_before": "0.3.9-dynamic-domain-context-collation-hotfix",
            "schema_version_after": "0.3.10-dynamic-service-context",
            "status": "applied",
            "receipt_path": "/tmp/dynamic-service-context.json",
        }
    ]


def test_apply_dynamic_service_context_migration_reseeds_when_already_applied() -> None:
    seeded_services: list[tuple[object, ...]] = []
    seeded_maps: list[tuple[object, ...]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if "FROM schema_migrations" in sql and "migration_entry_id" in sql:
            return {"migration_entry_id": 1}
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.10-dynamic-service-context"}
        if query_name == "dynamic_service_context.upsert_service":
            seeded_services.append(tuple(params))
            return None
        if query_name == "dynamic_service_context.upsert_domain_map":
            seeded_maps.append(tuple(params))
            return None
        if query_name == "dynamic_service_context.service_count":
            return {"n": len(seeded_services)}
        if query_name == "dynamic_service_context.domain_map_count":
            return {"n": len(seeded_maps)}
        if query_name == "dynamic_service_context.load_services":
            return []
        if query_name == "dynamic_service_context.load_domain_maps":
            return []
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    payload = catalog.apply_dynamic_service_context_migration(fake_run_sql)

    assert payload["already_applied"] is True
    assert payload["services_seeded"] == len(service_context.default_service_catalog_seed_rows())
    assert payload["domain_maps_seeded"] == len(service_context.default_service_domain_map_seed_rows())


def test_resolve_service_for_domain_prefers_package_specific_scope() -> None:
    services = tuple(service_context.default_service_catalog_seed_rows())
    maps = tuple(service_context.default_service_domain_map_seed_rows())

    bbc = service_context.resolve_service_for_domain(
        "bbc-global-app.api.bbc.com",
        package_name="bbc.mobile.news.ww",
        service_rows=services,
        map_rows=maps,
    )
    assert bbc["service_key"] == "bbc_first_party"
    assert bbc["owner_class"] == "first_party"

    bbc_live = service_context.resolve_service_for_domain(
        "api.live.bbcx-internal.com",
        package_name="bbc.mobile.news.ww",
        service_rows=services,
        map_rows=maps,
    )
    assert bbc_live["service_key"] == "bbc_first_party"
    assert bbc_live["role_class"] == "publisher_api"

    bbc_piano = service_context.resolve_service_for_domain(
        "buy-eu.piano.io",
        package_name="bbc.mobile.news.ww",
        service_rows=services,
        map_rows=maps,
    )
    assert bbc_piano["service_key"] == "piano"
    assert bbc_piano["service_category"] == "subscription_paywall"
    assert bbc_piano["role_class"] == "subscription_paywall"

    ads = service_context.resolve_service_for_domain(
        "googleads.g.doubleclick.net",
        package_name="bbc.mobile.news.ww",
        service_rows=services,
        map_rows=maps,
    )
    assert ads["service_key"] == "google_ads"
    assert ads["service_category"] == "adtech"

    unknown = service_context.resolve_service_for_domain(
        "unknown.example.org",
        package_name="bbc.mobile.news.ww",
        service_rows=services,
        map_rows=maps,
    )
    assert unknown["service_key"] is None
    assert unknown["service_display_name"] is None

    oracle = service_context.resolve_service_for_domain(
        "config.mtp.sag.us-ashburn-1.oci.oraclecloud.com",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert oracle["service_key"] == "oracle_cloud"
    assert oracle["service_category"] == "platform_infrastructure"
    assert oracle["role_class"] == "hosted_backend_infrastructure"

    meta_sdk = service_context.resolve_service_for_domain(
        "graph.facebook.com",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert meta_sdk["service_key"] == "meta_sdk"
    assert meta_sdk["owner_class"] == "third_party"

    meta_first_party = service_context.resolve_service_for_domain(
        "graph.facebook.com",
        package_name="com.facebook.katana",
        service_rows=services,
        map_rows=maps,
    )
    assert meta_first_party["service_key"] == "facebook_platform"
    assert meta_first_party["owner_class"] == "first_party"

    meta_infra = service_context.resolve_service_for_domain(
        "star.c10r.facebook.net",
        package_name="com.facebook.katana",
        service_rows=services,
        map_rows=maps,
    )
    assert meta_infra["service_key"] == "facebook_platform"
    assert meta_infra["owner_class"] == "first_party"

    meta_connect = service_context.resolve_service_for_domain(
        "connect.facebook.net",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert meta_connect["service_key"] == "meta_sdk"
    assert meta_connect["owner_class"] == "third_party"

    meta_b_graph = service_context.resolve_service_for_domain(
        "b-graph.facebook.com",
        package_name="com.facebook.katana",
        service_rows=services,
        map_rows=maps,
    )
    assert meta_b_graph["service_key"] == "facebook_platform"
    assert meta_b_graph["owner_class"] == "first_party"

    whatsapp_graph = service_context.resolve_service_for_domain(
        "graph.whatsapp.com",
        package_name="com.whatsapp",
        service_rows=services,
        map_rows=maps,
    )
    assert whatsapp_graph["service_key"] == "whatsapp_platform"
    assert whatsapp_graph["owner_class"] == "first_party"

    whatsapp_media = service_context.resolve_service_for_domain(
        "media-ord5-2.cdn.whatsapp.net",
        package_name="com.whatsapp",
        service_rows=services,
        map_rows=maps,
    )
    assert whatsapp_media["service_key"] == "whatsapp_platform"
    assert whatsapp_media["service_category"] == "social_platform"

    atlas = service_context.resolve_service_for_domain(
        "clk.atdmt.com",
        package_name="com.facebook.katana",
        service_rows=services,
        map_rows=maps,
    )
    assert atlas["service_key"] == "microsoft_ads_atlas"
    assert atlas["service_category"] == "adtech"

    instagram_api = service_context.resolve_service_for_domain(
        "i.instagram.com",
        package_name="com.instagram.android",
        service_rows=services,
        map_rows=maps,
    )
    assert instagram_api["service_key"] == "instagram_platform"
    assert instagram_api["owner_class"] == "first_party"

    instagram_cdn = service_context.resolve_service_for_domain(
        "scontent.cdninstagram.com",
        package_name="com.instagram.android",
        service_rows=services,
        map_rows=maps,
    )
    assert instagram_cdn["service_key"] == "instagram_media_cdn"
    assert instagram_cdn["role_class"] == "content_delivery"

    instagram_whatsapp = service_context.resolve_service_for_domain(
        "v.whatsapp.net",
        package_name="com.instagram.android",
        service_rows=services,
        map_rows=maps,
    )
    assert instagram_whatsapp["service_key"] == "whatsapp_platform"
    assert instagram_whatsapp["role_class"] == "realtime_call_transport"

    messenger_privacy_gateway = service_context.resolve_service_for_domain(
        "meta.privacy-gateway.cloudflare.com",
        package_name="com.facebook.orca",
        service_rows=services,
        map_rows=maps,
    )
    assert messenger_privacy_gateway["service_key"] == "cloudflare_privacy_gateway"
    assert messenger_privacy_gateway["role_class"] == "privacy_gateway"

    messenger_home = service_context.resolve_service_for_domain(
        "messenger.com",
        package_name="com.facebook.orca",
        service_rows=services,
        map_rows=maps,
    )
    assert messenger_home["service_key"] == "facebook_platform"
    assert messenger_home["owner_class"] == "first_party"
    assert messenger_home["role_class"] == "messaging_platform_api"

    x_api = service_context.resolve_service_for_domain(
        "api.x.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_api["service_key"] == "x_platform"
    assert x_api["owner_class"] == "first_party"

    x_ads = service_context.resolve_service_for_domain(
        "ads-api.x.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_ads["service_key"] == "x_ads_platform"
    assert x_ads["service_category"] == "adtech"

    time_google = service_context.resolve_service_for_domain(
        "time.google.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert time_google["service_key"] == "google_platform"
    assert time_google["owner_name"] == "Google"

    espn = service_context.resolve_service_for_domain(
        "espn.api.edge.bamgrid.com",
        package_name="com.espn.score_center",
        service_rows=services,
        map_rows=maps,
    )
    assert espn["service_key"] == "espn_first_party"
    assert espn["owner_class"] == "first_party"

    new_relic = service_context.resolve_service_for_domain(
        "mobile-collector.newrelic.com",
        package_name="com.espn.score_center",
        service_rows=services,
        map_rows=maps,
    )
    assert new_relic["service_key"] == "new_relic"
    assert new_relic["service_category"] == "analytics"

    nielsen = service_context.resolve_service_for_domain(
        "secure-dcr.vtwenty.com",
        package_name="com.espn.score_center",
        service_rows=services,
        map_rows=maps,
    )
    assert nielsen["service_key"] == "nielsen_dcr"
    assert nielsen["service_category"] == "analytics"

    x_api = service_context.resolve_service_for_domain(
        "api.x.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_api["service_key"] == "x_platform"
    assert x_api["owner_class"] == "first_party"

    x_media = service_context.resolve_service_for_domain(
        "pbs.twimg.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_media["service_key"] == "x_media_cdn"
    assert x_media["service_category"] == "content_delivery"

    x_probe = service_context.resolve_service_for_domain(
        "probe.twitter.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_probe["service_key"] == "x_platform"
    assert x_probe["role_class"] == "realtime_engagement"

    x_analytics = service_context.resolve_service_for_domain(
        "analytics.twitter.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_analytics["service_key"] == "x_platform"
    assert x_analytics["role_class"] == "analytics_measurement"

    x_chat = service_context.resolve_service_for_domain(
        "chat-ws.x.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_chat["service_key"] == "x_platform"
    assert x_chat["role_class"] == "realtime_engagement"

    x_video_s = service_context.resolve_service_for_domain(
        "video-s.twimg.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_video_s["service_key"] == "x_media_cdn"
    assert x_video_s["role_class"] == "content_delivery"

    x_ads = service_context.resolve_service_for_domain(
        "ads-api.x.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_ads["service_key"] == "x_ads_platform"
    assert x_ads["owner_class"] == "first_party"

    linkedin_home = service_context.resolve_service_for_domain(
        "www.linkedin.com",
        package_name="com.linkedin.android",
        service_rows=services,
        map_rows=maps,
    )
    assert linkedin_home["service_key"] == "linkedin_platform"
    assert linkedin_home["owner_class"] == "first_party"

    linkedin_perf = service_context.resolve_service_for_domain(
        "rum6.perf.linkedin.com",
        package_name="com.linkedin.android",
        service_rows=services,
        map_rows=maps,
    )
    assert linkedin_perf["service_key"] == "linkedin_platform"
    assert linkedin_perf["role_class"] == "performance_telemetry"

    linkedin_media = service_context.resolve_service_for_domain(
        "media.licdn.com",
        package_name="com.linkedin.android",
        service_rows=services,
        map_rows=maps,
    )
    assert linkedin_media["service_key"] == "linkedin_cdn"
    assert linkedin_media["service_category"] == "content_delivery"

    linkedin_bot_defense = service_context.resolve_service_for_domain(
        "collector-pxdojv695v.protechts.net",
        package_name="com.linkedin.android",
        service_rows=services,
        map_rows=maps,
    )
    assert linkedin_bot_defense["service_key"] == "human_security_bot_defense"
    assert linkedin_bot_defense["service_category"] == "security_or_bot_defense"

    linkedin_dns = service_context.resolve_service_for_domain(
        "b.ns1p.net",
        package_name="com.linkedin.android",
        service_rows=services,
        map_rows=maps,
    )
    assert linkedin_dns["service_key"] == "ns1_connect"
    assert linkedin_dns["role_class"] == "managed_dns_edge"

    pinterest_api = service_context.resolve_service_for_domain(
        "api.pinterest.com",
        package_name="com.pinterest",
        service_rows=services,
        map_rows=maps,
    )
    assert pinterest_api["service_key"] == "pinterest_platform"
    assert pinterest_api["owner_class"] == "first_party"

    pinterest_media = service_context.resolve_service_for_domain(
        "i.pinimg.com",
        package_name="com.pinterest",
        service_rows=services,
        map_rows=maps,
    )
    assert pinterest_media["service_key"] == "pinterest_media_cdn"
    assert pinterest_media["service_category"] == "content_delivery"

    pinterest_recaptcha = service_context.resolve_service_for_domain(
        "www.recaptcha.net",
        package_name="com.pinterest",
        service_rows=services,
        map_rows=maps,
    )
    assert pinterest_recaptcha["service_key"] == "google_recaptcha"
    assert pinterest_recaptcha["service_category"] == "security_or_bot_defense"

    reddit_api = service_context.resolve_service_for_domain(
        "gql-fed.reddit.com",
        package_name="com.reddit.frontpage",
        service_rows=services,
        map_rows=maps,
    )
    assert reddit_api["service_key"] == "reddit_platform"
    assert reddit_api["role_class"] == "community_platform_api"

    reddit_media = service_context.resolve_service_for_domain(
        "preview.redd.it",
        package_name="com.reddit.frontpage",
        service_rows=services,
        map_rows=maps,
    )
    assert reddit_media["service_key"] == "reddit_media_cdn"
    assert reddit_media["service_category"] == "content_delivery"

    appsflyer_onelink = service_context.resolve_service_for_domain(
        "i.sng.link",
        package_name="com.reddit.frontpage",
        service_rows=services,
        map_rows=maps,
    )
    assert appsflyer_onelink["service_key"] == "appsflyer"
    assert appsflyer_onelink["role_class"] == "attribution_deep_link"

    snapchat_api = service_context.resolve_service_for_domain(
        "gcp.api.snapchat.com",
        package_name="com.snapchat.android",
        service_rows=services,
        map_rows=maps,
    )
    assert snapchat_api["service_key"] == "snapchat_platform"
    assert snapchat_api["owner_class"] == "first_party"

    snapchat_cdn = service_context.resolve_service_for_domain(
        "cf-st.sc-cdn.net",
        package_name="com.snapchat.android",
        service_rows=services,
        map_rows=maps,
    )
    assert snapchat_cdn["service_key"] == "snapchat_cdn"
    assert snapchat_cdn["service_category"] == "content_delivery"

    signal_chat = service_context.resolve_service_for_domain(
        "chat.signal.org",
        package_name="org.thoughtcrime.securesms",
        service_rows=services,
        map_rows=maps,
    )
    assert signal_chat["service_key"] == "signal_platform"
    assert signal_chat["role_class"] == "encrypted_messaging_api"

    signal_turn = service_context.resolve_service_for_domain(
        "turn.cloudflare.com",
        package_name="org.thoughtcrime.securesms",
        service_rows=services,
        map_rows=maps,
    )
    assert signal_turn["service_key"] == "cloudflare_realtime_relay"
    assert signal_turn["role_class"] == "turn_relay"

    firebase_installations = service_context.resolve_service_for_domain(
        "firebaseinstallations.googleapis.com",
        package_name="org.thoughtcrime.securesms",
        service_rows=services,
        map_rows=maps,
    )
    assert firebase_installations["service_key"] == "firebase_installations"
    assert firebase_installations["role_class"] == "installation_identity"

    linkedin_google_stun = service_context.resolve_service_for_domain(
        "stun.l.google.com",
        package_name="com.linkedin.android",
        service_rows=services,
        map_rows=maps,
    )
    assert linkedin_google_stun["service_key"] == "google_platform"
    assert linkedin_google_stun["role_class"] == "stun_relay"

    google_play_media = service_context.resolve_service_for_domain(
        "play-lh.googleusercontent.com",
        package_name="com.reddit.frontpage",
        service_rows=services,
        map_rows=maps,
    )
    assert google_play_media["service_key"] == "google_platform"
    assert google_play_media["role_class"] == "content_delivery"

    reddit_recaptcha = service_context.resolve_service_for_domain(
        "www.recaptcha.net",
        package_name="com.reddit.frontpage",
        service_rows=services,
        map_rows=maps,
    )
    assert reddit_recaptcha["service_key"] == "google_recaptcha"

    linkedin_microsoft_fpt = service_context.resolve_service_for_domain(
        "fpt.dfp.microsoft.com",
        package_name="com.linkedin.android",
        service_rows=services,
        map_rows=maps,
    )
    assert linkedin_microsoft_fpt["service_key"] == "microsoft_fraud_protection"
    assert linkedin_microsoft_fpt["role_class"] == "device_fingerprinting"

    messenger_whatsapp = service_context.resolve_service_for_domain(
        "v.whatsapp.net",
        package_name="com.facebook.orca",
        service_rows=services,
        map_rows=maps,
    )
    assert messenger_whatsapp["service_key"] == "whatsapp_platform"
    assert messenger_whatsapp["role_class"] == "realtime_call_transport"

    tiktok_cdn = service_context.resolve_service_for_domain(
        "sf16-sg.tiktokcdn.com",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert tiktok_cdn["service_key"] == "tiktok_platform"
    assert tiktok_cdn["role_class"] == "content_delivery"

    tiktok_api = service_context.resolve_service_for_domain(
        "api16-normal-useast5.tiktokv.us",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert tiktok_api["service_key"] == "tiktok_platform"
    assert tiktok_api["role_class"] == "social_graph_api"

    tiktok_aggr = service_context.resolve_service_for_domain(
        "aggr16-normal.tiktokv.us",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert tiktok_aggr["service_key"] == "tiktok_platform"
    assert tiktok_aggr["role_class"] == "performance_telemetry"

    tiktok_tnc = service_context.resolve_service_for_domain(
        "tnc16-normal-useast5.tiktokv.us",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert tiktok_tnc["service_key"] == "tiktok_platform"
    assert tiktok_tnc["role_class"] == "sdk_configuration"

    tiktok_attribution = service_context.resolve_service_for_domain(
        "ug-attribution.tiktokv.us",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert tiktok_attribution["service_key"] == "tiktok_platform"
    assert tiktok_attribution["role_class"] == "attribution_measurement"

    google_time = service_context.resolve_service_for_domain(
        "time.google.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert google_time["service_key"] == "google_platform"
    assert google_time["service_category"] == "platform_infrastructure"

    akamai_whoami = service_context.resolve_service_for_domain(
        "whoami.akamai.net",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert akamai_whoami["service_key"] == "akamai_diagnostics"
    assert akamai_whoami["service_category"] == "platform_infrastructure"
    assert akamai_whoami["role_class"] == "network_diagnostics"

    mux = service_context.resolve_service_for_domain(
        "out053a3bejgh7t0phqa0csou.litix.io",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert mux["service_key"] == "mux_data"
    assert mux["owner_class"] == "third_party"

    freewheel = service_context.resolve_service_for_domain(
        "bea4.v.fwmrm.net",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert freewheel["service_key"] == "freewheel"
    assert freewheel["service_category"] == "adtech"

    brightline = service_context.resolve_service_for_domain(
        "cdn-media.brightline.tv",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert brightline["service_key"] == "brightline_ctv"
    assert brightline["owner_name"] == "BrightLine"

    wbd = service_context.resolve_service_for_domain(
        "default.any-any.prd.api.discomax.com",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert wbd["service_key"] == "wbd_streaming_platform"
    assert wbd["owner_class"] == "first_party"

    wbd_freeview = service_context.resolve_service_for_domain(
        "freeview.ngtv.io",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert wbd_freeview["service_key"] == "wbd_streaming_platform"
    assert wbd_freeview["role_class"] == "streaming_delivery"
    assert wbd_freeview["confidence"] == "medium"

    dianomi_worker = service_context.resolve_service_for_domain(
        "gpp-decoder.dianomi.workers.dev",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert dianomi_worker["service_key"] == "dianomi"
    assert dianomi_worker["service_category"] == "adtech"

    guardian_api = service_context.resolve_service_for_domain(
        "mobile.guardianapis.com",
        package_name="com.guardian",
        service_rows=services,
        map_rows=maps,
    )
    assert guardian_api["service_key"] == "guardian_first_party"
    assert guardian_api["role_class"] == "publisher_api"

    guardian_cdn = service_context.resolve_service_for_domain(
        "i.guim.co.uk",
        package_name="com.guardian",
        service_rows=services,
        map_rows=maps,
    )
    assert guardian_cdn["service_key"] == "guardian_first_party"
    assert guardian_cdn["role_class"] == "content_delivery"

    guardian_cmp = service_context.resolve_service_for_domain(
        "cdn.privacy-mgmt.com",
        package_name="com.guardian",
        service_rows=services,
        map_rows=maps,
    )
    assert guardian_cmp["service_key"] == "onetrust_cmp"
    assert guardian_cmp["role_class"] == "consent_management"

    bbc_cmp = service_context.resolve_service_for_domain(
        "cdn.privacy-mgmt.com",
        package_name="bbc.mobile.news.ww",
        service_rows=services,
        map_rows=maps,
    )
    assert bbc_cmp["service_key"] == "sourcepoint_cmp"
    assert bbc_cmp["role_class"] == "consent_management"

    guardian_braze = service_context.resolve_service_for_domain(
        "sdk.fra-01.braze.eu",
        package_name="com.guardian",
        service_rows=services,
        map_rows=maps,
    )
    assert guardian_braze["service_key"] == "braze_sdk"
    assert guardian_braze["service_category"] == "engagement"

    guardian_confiant = service_context.resolve_service_for_domain(
        "cdn.confiant-integrations.net",
        package_name="com.guardian",
        service_rows=services,
        map_rows=maps,
    )
    assert guardian_confiant["service_key"] == "confiant_ad_security"
    assert guardian_confiant["role_class"] == "ad_security"

    crashlytics = service_context.resolve_service_for_domain(
        "firebase-settings.crashlytics.com",
        package_name="com.guardian",
        service_rows=services,
        map_rows=maps,
    )
    assert crashlytics["service_key"] == "firebase_crashlytics"
    assert crashlytics["role_class"] == "crash_reporting"

    adjust = service_context.resolve_service_for_domain(
        "app.adjust.com",
        package_name="com.guardian",
        service_rows=services,
        map_rows=maps,
    )
    assert adjust["service_key"] == "adjust_attribution"
    assert adjust["role_class"] == "attribution_measurement"

    mapbox = service_context.resolve_service_for_domain(
        "config.mapbox.com",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert mapbox["service_key"] == "mapbox_platform"
    assert mapbox["role_class"] == "sdk_configuration"

    cnn_audience = service_context.resolve_service_for_domain(
        "audience.cnn.com",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert cnn_audience["service_key"] == "cnn_first_party"
    assert cnn_audience["role_class"] == "publisher_collection"

    cnn_smetrics = service_context.resolve_service_for_domain(
        "smetrics.cnn.com",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert cnn_smetrics["service_key"] == "cnn_first_party"
    assert cnn_smetrics["role_class"] == "publisher_collection"

    cloudflare = service_context.resolve_service_for_domain(
        "cdnjs.cloudflare.com",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert cloudflare["service_key"] == "cloudflare_cdnjs"
    assert cloudflare["role_class"] == "static_asset_delivery"

    amp = service_context.resolve_service_for_domain(
        "cdn.ampproject.org",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert amp["service_key"] == "google_amp_cache"
    assert amp["role_class"] == "content_delivery"

    smartadserver = service_context.resolve_service_for_domain(
        "ssbsync.smartadserver.com",
        package_name="com.cnn.mobile.android.phone",
        service_rows=services,
        map_rows=maps,
    )
    assert smartadserver["service_key"] == "equativ_smartadserver"
    assert smartadserver["role_class"] == "identity_sync"

    guardian_ophan = service_context.resolve_service_for_domain(
        "ophan.theguardian.com",
        package_name="com.guardian",
        service_rows=services,
        map_rows=maps,
    )
    assert guardian_ophan["service_key"] == "guardian_first_party"
    assert guardian_ophan["role_class"] == "publisher_collection"
