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

use crate::utils::{build_caa, parse_mx, parse_srv, parse_tlsa, strip_trailing_dot, unquote_txt};
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn,
    http::{HttpClient, HttpClientBuilder},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const DEFAULT_API_ENDPOINT: &str = "https://mijn.host/api/v2";
const MIJNHOST_MAX_TTL: u32 = i32::MAX as u32;
const ZONE_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct MijnHostProvider {
    client: HttpClient,
    endpoint: String,
    zones: Arc<Mutex<HashMap<String, (String, Instant)>>>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct Record {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    value: String,
    #[serde(default)]
    ttl: u32,
}

#[derive(Serialize)]
struct RecordsPayload<'a> {
    records: &'a [Record],
}

#[derive(Serialize)]
struct RecordPayload<'a> {
    record: &'a Record,
}

#[derive(Deserialize)]
struct ApiResponse<T> {
    #[serde(default)]
    status: u16,
    #[serde(default)]
    status_description: Option<String>,
    data: Option<T>,
}

#[derive(Deserialize)]
struct RecordsData {
    #[serde(default)]
    records: Vec<Record>,
}

#[derive(Deserialize)]
struct DomainsData {
    #[serde(default)]
    domains: Vec<DomainEntry>,
}

#[derive(Deserialize)]
struct DomainEntry {
    domain: String,
}

impl<T> ApiResponse<T> {
    fn check(&self, action: &str) -> crate::Result<()> {
        if self.status >= 400 {
            Err(Error::Api(format!(
                "Failed to {action}: {}",
                self.status_description
                    .as_deref()
                    .unwrap_or("no status description")
            )))
        } else {
            Ok(())
        }
    }

    fn into_data(self, action: &str) -> crate::Result<T> {
        self.check(action)?;
        self.data
            .ok_or_else(|| Error::Api(format!("Failed to {action}: response contained no data")))
    }
}

impl MijnHostProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("API-Key", api_key.as_ref())
            .with_timeout(timeout)
            .build();

        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            zones: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    async fn resolve_domain(&self, origin: &str) -> crate::Result<String> {
        let origin = origin.trim_end_matches('.').to_ascii_lowercase();

        if let Ok(guard) = self.zones.lock()
            && let Some((resolved, expiry)) = guard.get(&origin)
            && Instant::now() < *expiry
        {
            return Ok(resolved.clone());
        }

        let domains = self
            .client
            .get(format!("{}/domains", self.endpoint))
            .send_with_retry::<ApiResponse<DomainsData>>(3)
            .await?
            .into_data("list domains")?
            .domains;

        let mut candidate = origin.as_str();
        let resolved = loop {
            if let Some(entry) = domains.iter().find(|entry| {
                entry
                    .domain
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(candidate)
            }) {
                break entry.domain.trim_end_matches('.').to_ascii_lowercase();
            }

            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => {
                    return Err(Error::Api(format!(
                        "No mijn.host domain found for {origin}"
                    )));
                }
            }
        };

        if let Ok(mut guard) = self.zones.lock() {
            guard.insert(origin, (resolved.clone(), Instant::now() + ZONE_CACHE_TTL));
        }

        Ok(resolved)
    }

    async fn zone_records(&self, domain: &str) -> crate::Result<Vec<Record>> {
        self.client
            .get(format!("{}/domains/{domain}/dns", self.endpoint))
            .send_with_retry::<ApiResponse<RecordsData>>(3)
            .await?
            .into_data("list DNS records")
            .map(|data| data.records)
    }

    async fn put_zone_records(&self, domain: &str, records: &[Record]) -> crate::Result<()> {
        self.client
            .put(format!("{}/domains/{domain}/dns", self.endpoint))
            .with_body(RecordsPayload { records })?
            .send_with_retry::<ApiResponse<serde_json::Value>>(3)
            .await?
            .check("update DNS records")
    }

    async fn delete_zone_record(&self, domain: &str, record: &Record) -> crate::Result<()> {
        self.client
            .delete(format!("{}/domains/{domain}/dns", self.endpoint))
            .with_body(RecordPayload { record })?
            .send_with_retry::<ApiResponse<serde_json::Value>>(3)
            .await?
            .check("delete DNS record")
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let origin = origin.into_name().to_ascii_lowercase();
        let owner = name.into_name().to_ascii_lowercase();
        let domain = self.resolve_domain(&origin).await?;
        let rr_type = record_type.as_str();
        let ttl = ttl.min(MIJNHOST_MAX_TTL);
        let desired = build_values(record_type, records)?;

        let mut kept = Vec::new();
        let mut matched = Vec::new();
        for record in self.zone_records(&domain).await? {
            if matches_owner(&record, rr_type, &owner, &domain) {
                matched.push(record);
            } else {
                kept.push(record);
            }
        }

        if matched.len() == desired.len()
            && matched.iter().all(|record| record.ttl == ttl)
            && desired
                .iter()
                .all(|value| matched.iter().any(|record| &record.value == value))
        {
            return Ok(());
        }

        let owner_name = format!("{owner}.");
        for value in desired {
            kept.push(Record {
                record_type: rr_type.to_string(),
                name: owner_name.clone(),
                value,
                ttl,
            });
        }

        self.put_zone_records(&domain, &kept).await
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let origin = origin.into_name().to_ascii_lowercase();
        let owner = name.into_name().to_ascii_lowercase();
        let domain = self.resolve_domain(&origin).await?;
        let rr_type = record_type.as_str();
        let ttl = ttl.min(MIJNHOST_MAX_TTL);
        let desired = build_values(record_type, records)?;

        let mut all = self.zone_records(&domain).await?;
        let additions: Vec<String> = desired
            .into_iter()
            .filter(|value| {
                !all.iter().any(|record| {
                    matches_owner(record, rr_type, &owner, &domain) && &record.value == value
                })
            })
            .collect();

        if additions.is_empty() {
            return Ok(());
        }

        let owner_name = format!("{owner}.");
        for value in additions {
            all.push(Record {
                record_type: rr_type.to_string(),
                name: owner_name.clone(),
                value,
                ttl,
            });
        }

        self.put_zone_records(&domain, &all).await
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let origin = origin.into_name().to_ascii_lowercase();
        let owner = name.into_name().to_ascii_lowercase();
        let domain = self.resolve_domain(&origin).await?;
        let rr_type = record_type.as_str();
        let to_remove = build_values(record_type, records)?;

        for record in self.zone_records(&domain).await? {
            if matches_owner(&record, rr_type, &owner, &domain)
                && to_remove.iter().any(|value| value == &record.value)
            {
                self.delete_zone_record(&domain, &record).await?;
            }
        }

        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let origin = origin.into_name().to_ascii_lowercase();
        let owner = name.into_name().to_ascii_lowercase();
        let domain = self.resolve_domain(&origin).await?;
        let rr_type = record_type.as_str();

        self.zone_records(&domain)
            .await?
            .iter()
            .filter(|record| matches_owner(record, rr_type, &owner, &domain))
            .map(|record| parse_value(record_type, &record.value))
            .collect()
    }
}

fn normalize_name(name: &str, domain: &str) -> String {
    let trimmed = name.trim_end_matches('.').to_ascii_lowercase();

    if trimmed.is_empty() || trimmed == "@" {
        return domain.to_string();
    }

    if trimmed == domain || trimmed.ends_with(&format!(".{domain}")) {
        trimmed
    } else {
        format!("{trimmed}.{domain}")
    }
}

fn matches_owner(record: &Record, rr_type: &str, owner: &str, domain: &str) -> bool {
    record.record_type.eq_ignore_ascii_case(rr_type)
        && normalize_name(&record.name, domain) == owner
}

fn build_values(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<String>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(record_value(record));
    }
    Ok(out)
}

fn record_value(record: DnsRecord) -> String {
    match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(target) => target.into_fqdn().into_owned(),
        DnsRecord::NS(target) => target.into_fqdn().into_owned(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange.into_fqdn()),
        DnsRecord::TXT(text) => text,
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            srv.target.into_fqdn()
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    }
}

fn parse_value(record_type: DnsRecordType, value: &str) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => value
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A record: {e}"))),
        DnsRecordType::AAAA => value
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA record: {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(strip_trailing_dot(value).to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(strip_trailing_dot(value).to_string())),
        DnsRecordType::MX => parse_mx(value),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(value))),
        DnsRecordType::SRV => parse_srv(value),
        DnsRecordType::TLSA => parse_tlsa(value),
        DnsRecordType::CAA => parse_caa(value),
    }
}

fn parse_caa(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.splitn(3, ' ');
    let flags: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {value}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags: {e}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {value}")))?;
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {value}")))?;
    let unquoted = raw_value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw_value);

    build_caa(flags, tag, unquoted).map(DnsRecord::CAA)
}
