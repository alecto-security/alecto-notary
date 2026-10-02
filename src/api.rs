//! Contract C2: the store API. Read-only except locks. Loopback + bearer token.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::valid_id;
use crate::error::NotaryError;
use crate::locks::LockStore;
use crate::notary::Notary;
use crate::record::{Kind, Record};
use crate::timefmt::parse;

pub struct ApiState {
    pub notary: Arc<Notary>,
    pub locks: LockStore,
    pub cameras: Vec<String>,
    pub token: String,
}

pub fn router(state: ApiState) -> Router {
    let state = Arc::new(state);
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/cameras", get(cameras))
        .route("/v1/pubkey", get(pubkey))
        .route("/v1/segments", get(segments))
        .route("/v1/segments/{camera}/{seq}/file", get(segment_file))
        .route("/v1/locks", get(list_locks).post(create_lock))
        .route("/v1/locks/{id}", delete(delete_lock))
        .layer(middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state)
}

fn token_matches(provided: &str, expected: &str) -> bool {
    let a = Sha256::digest(provided.as_bytes());
    let b = Sha256::digest(expected.as_bytes());
    a.iter().zip(b.iter()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

async fn auth(State(state): State<Arc<ApiState>>, request: Request, next: Next) -> Response {
    let expected = format!("Bearer {}", state.token);
    let ok = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|h| token_matches(h, &expected));
    if ok {
        next.run(request).await
    } else {
        error(StatusCode::UNAUTHORIZED, "unauthorized")
    }
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn from_err(e: NotaryError) -> Response {
    match e {
        NotaryError::Config(m) => error(StatusCode::BAD_REQUEST, &m),
        NotaryError::Fail(m) if m == "lock not found" => error(StatusCode::NOT_FOUND, &m),
        NotaryError::Fail(m) => error(StatusCode::BAD_REQUEST, &m),
        other => error(StatusCode::INTERNAL_SERVER_ERROR, &other.to_string()),
    }
}

async fn status(State(state): State<Arc<ApiState>>) -> Response {
    let mut heads = BTreeMap::new();
    for cam in &state.cameras {
        match state.notary.head(cam) {
            Ok(Some(h)) => {
                heads.insert(
                    cam.clone(),
                    json!({ "seq": h.seq, "hash": h.hash, "end": crate::timefmt::fmt(h.end) }),
                );
            }
            Ok(None) => {
                heads.insert(cam.clone(), json!(null));
            }
            Err(e) => return from_err(e),
        }
    }
    Json(json!({
        "device_id": state.notary.device_id,
        "key_id": state.notary.key_id(),
        "clock_source": state.notary.clock_source,
        "chain_heads": heads,
    }))
    .into_response()
}

async fn cameras(State(state): State<Arc<ApiState>>) -> Response {
    Json(json!({ "cameras": state.cameras })).into_response()
}

async fn pubkey(State(state): State<Arc<ApiState>>) -> Response {
    Json(json!({
        "alg": "ed25519",
        "key_id": state.notary.key_id(),
        "public_key_b64": state.notary.public_b64(),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct SegQuery {
    camera: String,
    from: Option<String>,
    to: Option<String>,
}

async fn segments(State(state): State<Arc<ApiState>>, Query(q): Query<SegQuery>) -> Response {
    if !valid_id(&q.camera) || !state.cameras.contains(&q.camera) {
        return error(StatusCode::NOT_FOUND, "unknown camera");
    }
    let from = match q.from.as_deref().map(parse).transpose() {
        Ok(v) => v,
        Err(e) => return from_err(e),
    };
    let to = match q.to.as_deref().map(parse).transpose() {
        Ok(v) => v,
        Err(e) => return from_err(e),
    };
    let chain = match state.notary.store.read_chain(&q.camera) {
        Ok(c) => c,
        Err(e) => return from_err(e),
    };
    let overlaps = |r: &Record| -> bool {
        let (Ok(s), Ok(e)) = (parse(&r.start_utc), parse(&r.end_utc)) else {
            return false;
        };
        from.is_none_or(|f| e > f) && to.is_none_or(|t| s < t)
    };
    let hits: Vec<&Record> = chain
        .iter()
        .filter(|r| matches!(r.kind, Kind::Segment | Kind::Gap) && overlaps(r))
        .collect();
    // Return every record between the first and last hit so the slice stays
    // contiguous in seq and the consumer can verify the chain links itself.
    let records: Vec<&Record> = match (hits.first(), hits.last()) {
        (Some(a), Some(b)) => chain
            .iter()
            .filter(|r| r.seq >= a.seq.min(b.seq) && r.seq <= a.seq.max(b.seq))
            .collect(),
        _ => Vec::new(),
    };
    Json(json!({ "camera": q.camera, "records": records })).into_response()
}

async fn segment_file(
    State(state): State<Arc<ApiState>>,
    AxumPath((camera, seq)): AxumPath<(String, u64)>,
) -> Response {
    if !valid_id(&camera) || !state.cameras.contains(&camera) {
        return error(StatusCode::NOT_FOUND, "unknown camera");
    }
    let chain = match state.notary.store.read_chain(&camera) {
        Ok(c) => c,
        Err(e) => return from_err(e),
    };
    let Some(rec) = chain
        .iter()
        .find(|r| r.seq == seq && r.kind == Kind::Segment)
    else {
        return error(StatusCode::NOT_FOUND, "segment not found");
    };
    let rel = rec.file.clone().unwrap_or_default();
    let path = match state.notary.store.segment_path(&rel) {
        Ok(p) => p,
        Err(e) => return from_err(e),
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return error(StatusCode::NOT_FOUND, "segment file is gone (deleted by retention)"),
    };
    let mut response = Response::new(Body::from(bytes));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("video/mp2t"));
    if let Some(sha) = &rec.sha256 {
        if let Ok(v) = HeaderValue::from_str(sha) {
            response.headers_mut().insert("x-segment-sha256", v);
        }
    }
    response
}

async fn list_locks(State(state): State<Arc<ApiState>>) -> Response {
    match state.locks.list() {
        Ok(l) => Json(json!({ "locks": l })).into_response(),
        Err(e) => from_err(e),
    }
}

#[derive(Deserialize)]
struct LockBody {
    camera: String,
    from: String,
    to: String,
    case_id: String,
    actor: String,
    reason: String,
}

async fn create_lock(State(state): State<Arc<ApiState>>, Json(b): Json<LockBody>) -> Response {
    if !state.cameras.contains(&b.camera) {
        return error(StatusCode::NOT_FOUND, "unknown camera");
    }
    match state
        .locks
        .create(&b.camera, &b.from, &b.to, &b.case_id, &b.actor, &b.reason)
    {
        Ok(lock) => (StatusCode::CREATED, Json(lock)).into_response(),
        Err(e) => from_err(e),
    }
}

#[derive(Deserialize)]
struct ActorQuery {
    actor: String,
}

async fn delete_lock(
    State(state): State<Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<ActorQuery>,
) -> Response {
    match state.locks.delete(&id, &q.actor) {
        Ok(()) => Json(json!({ "ok": true, "id": id })).into_response(),
        Err(e) => from_err(e),
    }
}
