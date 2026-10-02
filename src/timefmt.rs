use chrono::{DateTime, SecondsFormat, Utc};

use crate::error::{NotaryError, Result};

/// RFC 3339 UTC with milliseconds, the only timestamp format in records.
pub fn fmt(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn parse(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| NotaryError::fail(format!("invalid RFC 3339 timestamp: {s}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_with_millis() {
        let dt = parse("2026-10-02T14:03:00.123Z").unwrap();
        assert_eq!(fmt(dt), "2026-10-02T14:03:00.123Z");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("yesterday").is_err());
    }
}
