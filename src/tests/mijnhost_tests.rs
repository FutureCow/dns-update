/*
 * Copyright Stalwart Labs LLC See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#[cfg(test)]
mod tests {
    use crate::{
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::mijnhost::MijnHostProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::{Value, json};
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> MijnHostProvider {
        MijnHostProvider::new("test_api_key", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn mock_domains(server: &mut ServerGuard, domains: Value) -> Mock {
        server
            .mock("GET", "/domains")
            .match_header("API-Key", "test_api_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "status": 200,
                    "status_description": "Request successful",
                    "data": { "domains": domains }
                })
                .to_string(),
            )
            .expect_at_least(1)
            .create()
    }

    fn mock_example_com(server: &mut ServerGuard) -> Mock {
        mock_domains(server, json!([{ "domain": "example.com" }]))
    }

    fn mock_get_records(server: &mut ServerGuard, records: Value) -> Mock {
        mock_get_records_times(server, records, 1)
    }

    fn mock_get_records_times(server: &mut ServerGuard, records: Value, times: usize) -> Mock {
        server
            .mock("GET", "/domains/example.com/dns")
            .match_header("API-Key", "test_api_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "status": 200,
                    "status_description": "Request successful",
                    "data": { "domain": "example.com", "records": records }
                })
                .to_string(),
            )
            .expect(times)
            .create()
    }

    fn mock_put_records(server: &mut ServerGuard, expected: Value) -> Mock {
        server
            .mock("PUT", "/domains/example.com/dns")
            .match_header("API-Key", "test_api_key")
            .match_body(Matcher::Json(json!({ "records": expected })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "status": 200, "status_description": "Saved" }).to_string())
            .create()
    }

    fn mock_delete_record(server: &mut ServerGuard, expected: Value) -> Mock {
        server
            .mock("DELETE", "/domains/example.com/dns")
            .match_header("API-Key", "test_api_key")
            .match_body(Matcher::Json(json!({ "record": expected })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "status": 200, "status_description": "Deleted" }).to_string())
            .create()
    }

    #[tokio::test]
    async fn set_rrset_preserves_unrelated_and_unmodelled_records() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(
            &mut server,
            json!([
                { "type": "A", "name": "example.com.", "value": "192.0.2.1", "ttl": 900 },
                { "type": "ALIAS", "name": "example.com.", "value": "target.example.net.", "ttl": 300 },
                { "type": "TXT", "name": "example.com.", "value": "v=spf1 -all", "ttl": 900 },
                { "type": "TXT", "name": "_acme-challenge", "value": "old-token", "ttl": 120 }
            ]),
        );
        let put = mock_put_records(
            &mut server,
            json!([
                { "type": "A", "name": "example.com.", "value": "192.0.2.1", "ttl": 900 },
                { "type": "ALIAS", "name": "example.com.", "value": "target.example.net.", "ttl": 300 },
                { "type": "TXT", "name": "example.com.", "value": "v=spf1 -all", "ttl": 900 },
                { "type": "TXT", "name": "_acme-challenge.example.com.", "value": "new-token", "ttl": 60 }
            ]),
        );

        let provider = setup_provider(&server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("new-token".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domains.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn set_rrset_is_a_noop_when_already_correct() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "_acme-challenge", "value": "token", "ttl": 60 }
            ]),
        );
        let put = server
            .mock("PUT", "/domains/example.com/dns")
            .with_status(200)
            .with_body(json!({ "status": 200 }).to_string())
            .expect(0)
            .create();

        let provider = setup_provider(&server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("token".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domains.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn set_rrset_rewrites_when_only_the_ttl_changes() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "_acme-challenge", "value": "token", "ttl": 900 }
            ]),
        );
        let put = mock_put_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "_acme-challenge.example.com.", "value": "token", "ttl": 60 }
            ]),
        );

        let provider = setup_provider(&server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("token".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domains.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn set_rrset_with_no_records_deletes_the_rrset() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(
            &mut server,
            json!([
                { "type": "A", "name": "example.com.", "value": "192.0.2.1", "ttl": 900 },
                { "type": "TXT", "name": "_acme-challenge", "value": "token", "ttl": 60 }
            ]),
        );
        let put = mock_put_records(
            &mut server,
            json!([
                { "type": "A", "name": "example.com.", "value": "192.0.2.1", "ttl": 900 }
            ]),
        );

        let provider = setup_provider(&server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                0,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domains.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_appends_and_skips_duplicates() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "_acme-challenge", "value": "first", "ttl": 60 }
            ]),
        );
        let put = mock_put_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "_acme-challenge", "value": "first", "ttl": 60 },
                { "type": "TXT", "name": "_acme-challenge.example.com.", "value": "second", "ttl": 60 }
            ]),
        );

        let provider = setup_provider(&server.url());
        let result = provider
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("first".to_string()),
                    DnsRecord::TXT("second".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        domains.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_is_a_noop_when_all_values_are_present() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "_acme-challenge", "value": "token", "ttl": 60 }
            ]),
        );
        let put = server
            .mock("PUT", "/domains/example.com/dns")
            .with_status(200)
            .with_body(json!({ "status": 200 }).to_string())
            .expect(0)
            .create();

        let provider = setup_provider(&server.url());
        let result = provider
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("token".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        domains.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_using_the_stored_name_form() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "_acme-challenge", "value": "gone", "ttl": 60 },
                { "type": "TXT", "name": "_acme-challenge", "value": "stays", "ttl": 60 }
            ]),
        );
        let delete = mock_delete_record(
            &mut server,
            json!({ "type": "TXT", "name": "_acme-challenge", "value": "gone", "ttl": 60 }),
        );

        let provider = setup_provider(&server.url());
        let result = provider
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("gone".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        domains.assert();
        get.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_is_a_noop_when_the_value_is_absent() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "_acme-challenge", "value": "stays", "ttl": 60 }
            ]),
        );
        let delete = server
            .mock("DELETE", "/domains/example.com/dns")
            .with_status(200)
            .with_body(json!({ "status": 200 }).to_string())
            .expect(0)
            .create();

        let provider = setup_provider(&server.url());
        let result = provider
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("absent".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        domains.assert();
        get.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn list_rrset_matches_relative_and_absolute_stored_names() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "_acme-challenge", "value": "relative", "ttl": 60 },
                { "type": "TXT", "name": "_acme-challenge.example.com.", "value": "absolute", "ttl": 60 },
                { "type": "TXT", "name": "other", "value": "unrelated", "ttl": 60 },
                { "type": "A", "name": "_acme-challenge", "value": "192.0.2.1", "ttl": 60 }
            ]),
        );

        let provider = setup_provider(&server.url());
        let records = provider
            .list_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                "example.com",
            )
            .await
            .expect("list_rrset failed");

        assert_eq!(
            records,
            vec![
                DnsRecord::TXT("relative".to_string()),
                DnsRecord::TXT("absolute".to_string())
            ]
        );
        domains.assert();
        get.assert();
    }

    #[tokio::test]
    async fn list_rrset_matches_the_apex_owner() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "example.com.", "value": "apex", "ttl": 900 },
                { "type": "TXT", "name": "@", "value": "at-sign", "ttl": 900 },
                { "type": "TXT", "name": "www", "value": "sub", "ttl": 900 }
            ]),
        );

        let provider = setup_provider(&server.url());
        let records = provider
            .list_rrset("example.com", DnsRecordType::TXT, "example.com")
            .await
            .expect("list_rrset failed");

        assert_eq!(
            records,
            vec![
                DnsRecord::TXT("apex".to_string()),
                DnsRecord::TXT("at-sign".to_string())
            ]
        );
        domains.assert();
        get.assert();
    }

    #[tokio::test]
    async fn list_rrset_parses_every_record_type() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server, json!([{ "domain": "example.com" }]));
        let get = mock_get_records_times(
            &mut server,
            json!([
                { "type": "MX", "name": "mixed", "value": "10 mail.example.com.", "ttl": 900 },
                { "type": "SRV", "name": "mixed", "value": "10 20 443 sip.example.com.", "ttl": 900 },
                { "type": "TLSA", "name": "mixed", "value": "3 1 1 deadbeef", "ttl": 900 },
                { "type": "CAA", "name": "mixed", "value": "0 issue \"letsencrypt.org\"", "ttl": 900 },
                { "type": "CNAME", "name": "mixed", "value": "target.example.net.", "ttl": 900 }
            ]),
            5,
        );

        let provider = setup_provider(&server.url());

        let mx = provider
            .list_rrset("mixed.example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("MX list failed");
        assert_eq!(
            mx,
            vec![DnsRecord::MX(MXRecord {
                priority: 10,
                exchange: "mail.example.com".to_string()
            })]
        );

        let srv = provider
            .list_rrset("mixed.example.com", DnsRecordType::SRV, "example.com")
            .await
            .expect("SRV list failed");
        assert_eq!(
            srv,
            vec![DnsRecord::SRV(SRVRecord {
                priority: 10,
                weight: 20,
                port: 443,
                target: "sip.example.com".to_string()
            })]
        );

        let tlsa = provider
            .list_rrset("mixed.example.com", DnsRecordType::TLSA, "example.com")
            .await
            .expect("TLSA list failed");
        assert_eq!(
            tlsa,
            vec![DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneEe,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: vec![0xde, 0xad, 0xbe, 0xef]
            })]
        );

        let caa = provider
            .list_rrset("mixed.example.com", DnsRecordType::CAA, "example.com")
            .await
            .expect("CAA list failed");
        assert_eq!(
            caa,
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![]
            })]
        );

        let cname = provider
            .list_rrset("mixed.example.com", DnsRecordType::CNAME, "example.com")
            .await
            .expect("CNAME list failed");
        assert_eq!(
            cname,
            vec![DnsRecord::CNAME("target.example.net".to_string())]
        );

        domains.assert();
        get.assert();
    }

    #[tokio::test]
    async fn set_rrset_renders_the_wire_format_for_every_record_type() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(&mut server, json!([]));
        let put = mock_put_records(
            &mut server,
            json!([
                { "type": "MX", "name": "mixed.example.com.", "value": "10 mail.example.com.", "ttl": 900 }
            ]),
        );

        let provider = setup_provider(&server.url());
        provider
            .set_rrset(
                "mixed.example.com",
                DnsRecordType::MX,
                900,
                vec![DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mail.example.com".to_string(),
                })],
                "example.com",
            )
            .await
            .expect("MX set_rrset failed");

        domains.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn zone_discovery_walks_up_the_origin_labels() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server, json!([{ "domain": "example.com" }]));
        let get = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "status": 200,
                    "data": {
                        "domain": "example.com",
                        "records": [
                            { "type": "TXT", "name": "host.sub", "value": "deep", "ttl": 60 }
                        ]
                    }
                })
                .to_string(),
            )
            .create();

        let provider = setup_provider(&server.url());
        let records = provider
            .list_rrset(
                "host.sub.example.com",
                DnsRecordType::TXT,
                "sub.example.com",
            )
            .await
            .expect("list_rrset failed");

        assert_eq!(records, vec![DnsRecord::TXT("deep".to_string())]);
        domains.assert();
        get.assert();
    }

    #[tokio::test]
    async fn unknown_zone_is_reported_as_an_api_error() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server, json!([{ "domain": "other.com" }]));

        let provider = setup_provider(&server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::TXT, "example.com")
            .await;

        match result {
            Err(Error::Api(message)) => {
                assert!(
                    message.contains("No mijn.host domain found"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected Error::Api, got {other:?}"),
        }
        domains.assert();
    }

    #[tokio::test]
    async fn record_type_mismatch_is_rejected() {
        let mut server = mockito::Server::new_async().await;
        let _domains = mock_example_com(&mut server);

        let provider = setup_provider(&server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                "example.com",
            )
            .await;

        match result {
            Err(Error::Api(message)) => {
                assert!(
                    message.contains("RRSet record type mismatch"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected Error::Api, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn body_level_error_status_is_surfaced() {
        let mut server = mockito::Server::new_async().await;
        let domains = server
            .mock("GET", "/domains")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "status": 401,
                    "status_description": "No valid API key set."
                })
                .to_string(),
            )
            .create();

        let provider = setup_provider(&server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::TXT, "example.com")
            .await;

        match result {
            Err(Error::Api(message)) => {
                assert!(
                    message.contains("No valid API key set."),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected Error::Api, got {other:?}"),
        }
        domains.assert();
    }

    #[tokio::test]
    async fn ttl_is_clamped_to_the_api_maximum() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_example_com(&mut server);
        let get = mock_get_records(&mut server, json!([]));
        let put = mock_put_records(
            &mut server,
            json!([
                { "type": "TXT", "name": "www.example.com.", "value": "token", "ttl": 2147483647u32 }
            ]),
        );

        let provider = setup_provider(&server.url());
        provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                u32::MAX,
                vec![DnsRecord::TXT("token".to_string())],
                "example.com",
            )
            .await
            .expect("set_rrset failed");

        domains.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    #[ignore = "Requires MIJNHOST_API_KEY and MIJNHOST_ORIGIN"]
    async fn integration_test() {
        let api_key = std::env::var("MIJNHOST_API_KEY").unwrap_or_default();
        let origin = std::env::var("MIJNHOST_ORIGIN").unwrap_or_default();
        assert!(!api_key.is_empty(), "Set MIJNHOST_API_KEY");
        assert!(!origin.is_empty(), "Set MIJNHOST_ORIGIN (e.g. example.com)");

        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let owner = format!("dnsupdate-poc-{run_id}.{origin}");

        let provider = MijnHostProvider::new(&api_key, Some(Duration::from_secs(30)));

        let list = async |record_type: DnsRecordType| {
            provider
                .list_rrset(owner.as_str(), record_type, origin.as_str())
                .await
                .unwrap_or_else(|err| panic!("list {owner} failed: {err}"))
        };

        assert!(
            list(DnsRecordType::TXT).await.is_empty(),
            "test owner {owner} is not empty before the run"
        );

        provider
            .set_rrset(
                owner.as_str(),
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("first".to_string())],
                origin.as_str(),
            )
            .await
            .expect("set_rrset failed");
        assert_eq!(
            list(DnsRecordType::TXT).await,
            vec![DnsRecord::TXT("first".to_string())]
        );

        provider
            .add_to_rrset(
                owner.as_str(),
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("second".to_string())],
                origin.as_str(),
            )
            .await
            .expect("add_to_rrset failed");
        let mut both = list(DnsRecordType::TXT).await;
        both.sort_by_key(|record| record.to_string());
        assert_eq!(
            both,
            vec![
                DnsRecord::TXT("first".to_string()),
                DnsRecord::TXT("second".to_string())
            ]
        );

        provider
            .remove_from_rrset(
                owner.as_str(),
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("first".to_string())],
                origin.as_str(),
            )
            .await
            .expect("remove_from_rrset failed");
        assert_eq!(
            list(DnsRecordType::TXT).await,
            vec![DnsRecord::TXT("second".to_string())]
        );

        provider
            .set_rrset(
                owner.as_str(),
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("192.0.2.1".parse().unwrap()),
                    DnsRecord::A("192.0.2.2".parse().unwrap()),
                ],
                origin.as_str(),
            )
            .await
            .expect("A set_rrset failed");
        let mut addresses = list(DnsRecordType::A).await;
        addresses.sort_by_key(|record| record.to_string());
        assert_eq!(
            addresses,
            vec![
                DnsRecord::A("192.0.2.1".parse().unwrap()),
                DnsRecord::A("192.0.2.2".parse().unwrap())
            ]
        );
        assert_eq!(
            list(DnsRecordType::TXT).await,
            vec![DnsRecord::TXT("second".to_string())],
            "writing the A RRSet disturbed the TXT RRSet at the same owner"
        );

        for record_type in [DnsRecordType::TXT, DnsRecordType::A] {
            provider
                .set_rrset(owner.as_str(), record_type, 0, vec![], origin.as_str())
                .await
                .unwrap_or_else(|err| panic!("cleanup of {record_type:?} failed: {err}"));
            assert!(list(record_type).await.is_empty());
        }
    }

    async fn probe_rrset(
        provider: &MijnHostProvider,
        owner: &str,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: &str,
    ) -> Result<(), String> {
        provider
            .set_rrset(owner, record_type, 300, records.clone(), origin)
            .await
            .map_err(|err| format!("set_rrset: {err}"))?;

        let mut got = provider
            .list_rrset(owner, record_type, origin)
            .await
            .map_err(|err| format!("list_rrset: {err}"))?;
        let mut want = records;
        got.sort_by_key(|record| record.to_string());
        want.sort_by_key(|record| record.to_string());

        if got == want {
            Ok(())
        } else {
            Err(format!(
                "round-trip mismatch: wrote {want:?}, read back {got:?}"
            ))
        }
    }

    #[tokio::test]
    #[ignore = "Requires MIJNHOST_API_KEY and MIJNHOST_ORIGIN"]
    async fn integration_record_type_support() {
        let api_key = std::env::var("MIJNHOST_API_KEY").unwrap_or_default();
        let origin = std::env::var("MIJNHOST_ORIGIN").unwrap_or_default();
        assert!(!api_key.is_empty(), "Set MIJNHOST_API_KEY");
        assert!(!origin.is_empty(), "Set MIJNHOST_ORIGIN (e.g. example.com)");

        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let base = format!("dnsupdate-poc-{run_id}");
        let provider = MijnHostProvider::new(&api_key, Some(Duration::from_secs(30)));

        let long_txt = format!("v=DKIM1; k=rsa; p={}", "A".repeat(300));

        let cases: Vec<(&str, String, DnsRecordType, Vec<DnsRecord>)> = vec![
            (
                "TXT short",
                format!("{base}-txt.{origin}"),
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("simple-value".to_string())],
            ),
            (
                "TXT >255 bytes",
                format!("{base}-txtlong.{origin}"),
                DnsRecordType::TXT,
                vec![DnsRecord::TXT(long_txt)],
            ),
            (
                "TXT multi-value",
                format!("{base}-txtmulti.{origin}"),
                DnsRecordType::TXT,
                vec![
                    DnsRecord::TXT("value-one".to_string()),
                    DnsRecord::TXT("value-two".to_string()),
                ],
            ),
            (
                "MX",
                format!("{base}-mx.{origin}"),
                DnsRecordType::MX,
                vec![DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: format!("mail.{origin}"),
                })],
            ),
            (
                "CNAME",
                format!("{base}-cname.{origin}"),
                DnsRecordType::CNAME,
                vec![DnsRecord::CNAME("target.example.net".to_string())],
            ),
            (
                "NS",
                format!("{base}-ns.{origin}"),
                DnsRecordType::NS,
                vec![DnsRecord::NS("ns1.example.net".to_string())],
            ),
            (
                "SRV",
                format!("_sip._tcp.{base}-srv.{origin}"),
                DnsRecordType::SRV,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 20,
                    port: 5060,
                    target: format!("sip.{origin}"),
                })],
            ),
            (
                "TLSA",
                format!("_25._tcp.{base}-tlsa.{origin}"),
                DnsRecordType::TLSA,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xde, 0xad, 0xbe, 0xef],
                })],
            ),
            (
                "CAA",
                format!("{base}-caa.{origin}"),
                DnsRecordType::CAA,
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                })],
            ),
        ];

        let mut results = Vec::new();
        for (label, owner, record_type, records) in cases {
            let outcome = probe_rrset(&provider, &owner, record_type, records, &origin).await;

            if let Err(err) = provider
                .set_rrset(owner.as_str(), record_type, 0, vec![], origin.as_str())
                .await
            {
                println!("warning: could not clean up {owner}: {err}");
            }

            results.push((label, outcome));
        }

        println!("\nmijn.host record type support for {origin}:");
        for (label, outcome) in &results {
            match outcome {
                Ok(()) => println!("  {label:<16} OK"),
                Err(err) => println!("  {label:<16} FAILED   {err}"),
            }
        }
        println!();

        let failures: Vec<&str> = results
            .iter()
            .filter(|(_, outcome)| outcome.is_err())
            .map(|(label, _)| *label)
            .collect();
        assert!(
            failures.is_empty(),
            "record types that did not round-trip: {failures:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writes_to_one_zone_do_not_clobber_each_other() {
        use std::sync::{Arc, Mutex as StdMutex};

        let mut server = mockito::Server::new_async().await;
        let _domains = mock_example_com(&mut server);

        let zone: Arc<StdMutex<Vec<Value>>> = Arc::new(StdMutex::new(Vec::new()));

        let get_zone = zone.clone();
        let _get = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |_| {
                let records = get_zone.lock().unwrap().clone();
                std::thread::sleep(Duration::from_millis(150));
                serde_json::to_vec(&json!({
                    "status": 200,
                    "data": { "domain": "example.com", "records": records }
                }))
                .unwrap()
            })
            .expect_at_least(2)
            .create();

        let put_zone = zone.clone();
        let _put = server
            .mock("PUT", "/domains/example.com/dns")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |req| {
                let body: Value = serde_json::from_slice(req.body().unwrap()).unwrap();
                let records = body["records"].as_array().cloned().unwrap_or_default();
                *put_zone.lock().unwrap() = records;
                serde_json::to_vec(&json!({ "status": 200 })).unwrap()
            })
            .expect_at_least(2)
            .create();

        let provider = setup_provider(&server.url());
        let first = provider.set_rrset(
            "one.example.com",
            DnsRecordType::TXT,
            60,
            vec![DnsRecord::TXT("first".to_string())],
            "example.com",
        );
        let second = provider.set_rrset(
            "two.example.com",
            DnsRecordType::TXT,
            60,
            vec![DnsRecord::TXT("second".to_string())],
            "example.com",
        );
        let (a, b) = tokio::join!(first, second);
        a.expect("first set_rrset failed");
        b.expect("second set_rrset failed");

        let final_zone = zone.lock().unwrap().clone();
        let names: Vec<&str> = final_zone
            .iter()
            .filter_map(|record| record["name"].as_str())
            .collect();

        assert!(
            names.contains(&"one.example.com."),
            "the first RRSet was clobbered by the concurrent write: {names:?}"
        );
        assert!(
            names.contains(&"two.example.com."),
            "the second RRSet was clobbered by the concurrent write: {names:?}"
        );
    }
}
