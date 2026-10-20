use std::env;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use qrcodegen::{QrCode, QrCodeEcc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use tracing_subscriber::EnvFilter;
use verifier_core::{CredentialClaims, SignedCredential};

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    base_url: String,
}

#[derive(Debug)]
enum ApiError {
    BadRequest(String),
    NotFound(String),
    Conflict(String),
    Internal,
}

impl ApiError {
    fn message(&self) -> &str {
        match self {
            Self::BadRequest(message) | Self::NotFound(message) | Self::Conflict(message) => {
                message
            }
            Self::Internal => "internal error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(json!({ "error": self.message() }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database error");
        match error {
            sqlx::Error::RowNotFound => Self::NotFound("not found".into()),
            _ => Self::Internal,
        }
    }
}

impl From<verifier_core::Error> for ApiError {
    fn from(error: verifier_core::Error) -> Self {
        tracing::error!(%error, "verifier error");
        Self::Internal
    }
}

#[derive(Deserialize)]
struct CreateIssuerRequest {
    name: String,
}

#[derive(Serialize)]
struct IssuerResponse {
    id: String,
    name: String,
    status: String,
    key_id: Option<String>,
    public_key_hex: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct IssuerKeyResponse {
    key_id: String,
    issuer_id: String,
    public_key_hex: String,
    status: String,
    created_at: String,
    retired_at: Option<String>,
    revoked_at: Option<String>,
    revocation_reason: Option<String>,
}

#[derive(Serialize)]
struct IssuerKeysResponse {
    issuer_id: String,
    keys: Vec<IssuerKeyResponse>,
}

#[derive(Serialize)]
struct RotateKeyResponse {
    issuer_id: String,
    key: IssuerKeyResponse,
    previous_key_id: Option<String>,
}

#[derive(Deserialize)]
struct RevokeKeyRequest {
    reason: String,
}

#[derive(Deserialize)]
struct CreateSchemaRequest {
    name: String,
    #[serde(default = "default_schema_version")]
    version: i32,
    schema_json: Value,
}

fn default_schema_version() -> i32 {
    1
}

#[derive(Serialize)]
struct SchemaResponse {
    id: String,
    issuer_id: String,
    name: String,
    version: i32,
    schema_json: Value,
    created_at: String,
}

#[derive(Deserialize)]
struct IssueRequest {
    issuer_id: String,
    schema_id: String,
    subject_ref: String,
    claims: Value,
    #[serde(default)]
    idempotency_key: Option<String>,
}

#[derive(Serialize)]
struct IssuedCredentialResponse {
    id: String,
    issuer_id: String,
    schema_id: String,
    subject_ref: String,
    credential_type: String,
    status: String,
    key_id: Option<String>,
    claims: Value,
    signed_credential: SignedCredential,
    share_url: String,
    issued_at: String,
}

#[derive(Deserialize)]
struct BulkIssueRequest {
    items: Vec<IssueRequest>,
}

#[derive(Serialize)]
struct BulkIssueResponse {
    issued: Vec<IssuedCredentialResponse>,
    errors: Vec<BulkIssueError>,
}

#[derive(Serialize)]
struct BulkIssueError {
    index: usize,
    error: String,
}

#[derive(Deserialize)]
struct RevokeRequest {
    reason: String,
}

#[derive(Serialize)]
struct RevocationResponse {
    credential_id: String,
    status: String,
    reason: String,
    revoked_at: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    status: String,
    credential_id: String,
    issuer_id: String,
    issuer_name: String,
    subject_ref: String,
    credential_type: String,
    claims: Value,
    issued_at: String,
    revoked_at: Option<String>,
    revocation_reason: Option<String>,
    key_id: Option<String>,
    key_status: Option<String>,
    signature_valid: bool,
    issuer_trusted: bool,
    log_leaf_hash: Option<String>,
}

#[derive(Serialize)]
struct ProofResponse {
    credential_id: String,
    leaf_hash: String,
    leaf_index: usize,
    tree_size: usize,
    root_hash: String,
    audit_path: Vec<String>,
}

#[derive(Deserialize)]
struct LogRootQuery {
    tree_size: Option<usize>,
}

#[derive(Serialize)]
struct LogRootResponse {
    tree_size: usize,
    root_hash: String,
}

#[derive(Deserialize)]
struct LogConsistencyQuery {
    first_size: usize,
    second_size: Option<usize>,
}

#[derive(Serialize)]
struct LogConsistencyResponse {
    first_size: usize,
    second_size: usize,
    first_root: String,
    second_root: String,
    proof: Vec<String>,
}

#[derive(Serialize)]
struct StatusListEntry {
    credential_id: String,
    reason: String,
    revoked_at: String,
}

#[derive(Serialize)]
struct StatusListResponse {
    generated_at: String,
    active: Vec<String>,
    revoked: Vec<StatusListEntry>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let database_url = env::var("DATABASE_URL")?;
    let base_url = env::var("PUBLIC_BASE_URL").unwrap_or_else(|_| "http://localhost:8082".into());
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    let app = Router::new()
        .route("/health", get(health))
        .route("/health/db", get(health_db))
        .route("/version", get(version))
        .route("/api/issuers", post(create_issuer))
        .route("/api/issuers/{id}", get(get_issuer))
        .route("/api/issuers/{id}/trust", post(trust_issuer))
        .route(
            "/api/issuers/{id}/schemas",
            get(list_schemas).post(create_schema),
        )
        .route("/api/issuers/{id}/public-key", get(get_public_key))
        .route(
            "/api/issuers/{id}/keys",
            get(list_issuer_keys).post(rotate_issuer_key),
        )
        .route(
            "/api/issuers/{id}/keys/{key_id}/revoke",
            post(revoke_issuer_key),
        )
        .route("/api/credentials", post(issue_credential))
        .route("/api/credentials/bulk", post(bulk_issue))
        .route("/api/credentials/{id}", get(get_credential))
        .route("/api/credentials/{id}/qr.svg", get(credential_qr))
        .route("/api/credentials/{id}/proof", get(credential_proof))
        .route("/api/credentials/{id}/revoke", post(revoke_credential))
        .route("/api/verify/{id}", get(verify_credential))
        .route("/api/status-list", get(status_list))
        .route("/api/log/root", get(log_root))
        .route("/api/log/consistency", get(log_consistency))
        .with_state(AppState { pool, base_url });

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    tracing::info!(%bind_addr, "attest api listening");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok", "service": "attest"}))
}

async fn version() -> Json<Value> {
    Json(json!({"version": verifier_core::VERSION}))
}

async fn health_db(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "database": "ok"})),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "error", "database": "unavailable"})),
        ),
    }
}

async fn create_issuer(
    State(state): State<AppState>,
    Json(request): Json<CreateIssuerRequest>,
) -> Result<(StatusCode, Json<IssuerResponse>), ApiError> {
    if request.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }

    let seed_hex = verifier_core::generate_seed_hex();
    let row = sqlx::query(
        "WITH new_issuer AS (
             INSERT INTO issuers (name, status, signing_seed_hex)
             VALUES ($1, 'pending', $2)
             RETURNING id, name, status, created_at
         ), new_key AS (
             INSERT INTO issuer_keys (issuer_id, signing_seed_hex)
             SELECT id, $2 FROM new_issuer
             RETURNING id, issuer_id, signing_seed_hex
         )
         SELECT i.id::text, i.name, i.status, i.created_at::text,
                k.id::text AS key_id, k.signing_seed_hex AS key_seed_hex
         FROM new_issuer i
         JOIN new_key k ON k.issuer_id = i.id",
    )
    .bind(request.name.trim())
    .bind(&seed_hex)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(row_to_issuer(&row)?)))
}

async fn get_issuer(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<IssuerResponse>, ApiError> {
    validate_uuid(&id)?;
    let row = fetch_issuer_row(&state, &id).await?;

    Ok(Json(row_to_issuer(&row)?))
}

async fn trust_issuer(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<IssuerResponse>, ApiError> {
    validate_uuid(&id)?;
    let result = sqlx::query(
        "UPDATE issuers SET status = 'trusted'
         WHERE id = $1::uuid AND status IN ('pending', 'suspended')",
    )
    .bind(&id)
    .execute(&state.pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::Conflict(
            "issuer cannot be trusted in its current state".into(),
        ));
    }

    let row = fetch_issuer_row(&state, &id).await?;
    Ok(Json(row_to_issuer(&row)?))
}

async fn get_public_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    validate_uuid(&id)?;
    let row = sqlx::query(
        "SELECT k.id::text AS key_id, k.signing_seed_hex
         FROM issuer_keys k
         WHERE k.issuer_id = $1::uuid AND k.status = 'active'",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::Conflict("issuer has no active signing key".into()))?;
    let seed_hex: String = row.get("signing_seed_hex");
    let signing_key = verifier_core::signing_key_from_seed_hex(&seed_hex)?;

    Ok(Json(json!({
        "issuer_id": id,
        "key_id": row.get::<String, _>("key_id"),
        "public_key_hex": verifier_core::verifying_key_hex(&signing_key.verifying_key()),
        "status": "active",
    })))
}

async fn list_issuer_keys(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<IssuerKeysResponse>, ApiError> {
    validate_uuid(&id)?;
    sqlx::query_scalar::<_, String>("SELECT id::text FROM issuers WHERE id = $1::uuid")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;

    let rows = sqlx::query(
        "SELECT id::text AS key_id, issuer_id::text, signing_seed_hex, status,
                created_at::text, retired_at::text, revoked_at::text, revocation_reason
         FROM issuer_keys
         WHERE issuer_id = $1::uuid
         ORDER BY created_at DESC, id DESC",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(IssuerKeysResponse {
        issuer_id: id,
        keys: rows.iter().map(row_to_key).collect::<Result<_, _>>()?,
    }))
}

async fn rotate_issuer_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<RotateKeyResponse>), ApiError> {
    validate_uuid(&id)?;
    let seed_hex = verifier_core::generate_seed_hex();

    let mut tx = state.pool.begin().await?;
    let issuer_status: String =
        sqlx::query_scalar("SELECT status FROM issuers WHERE id = $1::uuid FOR UPDATE")
            .bind(&id)
            .fetch_one(&mut *tx)
            .await?;
    if issuer_status == "revoked" {
        return Err(ApiError::Conflict(
            "issuer cannot rotate keys in its current state".into(),
        ));
    }

    let previous_key_id: Option<String> = sqlx::query_scalar(
        "UPDATE issuer_keys
         SET status = 'retired', retired_at = now()
         WHERE issuer_id = $1::uuid AND status = 'active'
         RETURNING id::text",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;

    let row = sqlx::query(
        "INSERT INTO issuer_keys (issuer_id, signing_seed_hex, status)
         VALUES ($1::uuid, $2, 'active')
         RETURNING id::text AS key_id, issuer_id::text, signing_seed_hex, status,
                   created_at::text, retired_at::text, revoked_at::text, revocation_reason",
    )
    .bind(&id)
    .bind(&seed_hex)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(RotateKeyResponse {
            issuer_id: id,
            key: row_to_key(&row)?,
            previous_key_id,
        }),
    ))
}

async fn revoke_issuer_key(
    State(state): State<AppState>,
    Path((id, key_id)): Path<(String, String)>,
    Json(request): Json<RevokeKeyRequest>,
) -> Result<Json<IssuerKeyResponse>, ApiError> {
    validate_uuid(&id)?;
    validate_uuid(&key_id)?;
    if request.reason.trim().is_empty() {
        return Err(ApiError::BadRequest("reason is required".into()));
    }

    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        "SELECT id::text AS key_id, issuer_id::text, signing_seed_hex, status,
                created_at::text, retired_at::text, revoked_at::text, revocation_reason
         FROM issuer_keys
         WHERE id = $1::uuid AND issuer_id = $2::uuid
         FOR UPDATE",
    )
    .bind(&key_id)
    .bind(&id)
    .fetch_one(&mut *tx)
    .await?;
    let status: String = row.get("status");

    let row = if status == "revoked" {
        row
    } else {
        sqlx::query(
            "UPDATE issuer_keys
             SET status = 'revoked', revoked_at = now(), revocation_reason = $3
             WHERE id = $1::uuid AND issuer_id = $2::uuid
             RETURNING id::text AS key_id, issuer_id::text, signing_seed_hex, status,
                       created_at::text, retired_at::text, revoked_at::text,
                       revocation_reason",
        )
        .bind(&key_id)
        .bind(&id)
        .bind(request.reason.trim())
        .fetch_one(&mut *tx)
        .await?
    };
    tx.commit().await?;

    Ok(Json(row_to_key(&row)?))
}

async fn create_schema(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<CreateSchemaRequest>,
) -> Result<(StatusCode, Json<SchemaResponse>), ApiError> {
    validate_uuid(&id)?;
    if request.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    if request.version <= 0 {
        return Err(ApiError::BadRequest("version must be positive".into()));
    }

    sqlx::query_scalar::<_, String>("SELECT id::text FROM issuers WHERE id = $1::uuid")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;

    let row = sqlx::query(
        "INSERT INTO credential_schemas (issuer_id, name, version, schema_json)
         VALUES ($1::uuid, $2, $3, $4)
         RETURNING id::text, issuer_id::text, name, version, schema_json, created_at::text",
    )
    .bind(&id)
    .bind(request.name.trim())
    .bind(request.version)
    .bind(&request.schema_json)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(row_to_schema(&row))))
}

async fn list_schemas(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<SchemaResponse>>, ApiError> {
    validate_uuid(&id)?;
    let rows = sqlx::query(
        "SELECT id::text, issuer_id::text, name, version, schema_json, created_at::text
         FROM credential_schemas
         WHERE issuer_id = $1::uuid
         ORDER BY name, version DESC",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows.iter().map(row_to_schema).collect()))
}

async fn issue_credential(
    State(state): State<AppState>,
    Json(request): Json<IssueRequest>,
) -> Result<(StatusCode, Json<IssuedCredentialResponse>), ApiError> {
    let issued = issue_one(&state, request).await?;
    Ok((StatusCode::CREATED, Json(issued)))
}

async fn bulk_issue(
    State(state): State<AppState>,
    Json(request): Json<BulkIssueRequest>,
) -> Result<Json<BulkIssueResponse>, ApiError> {
    if request.items.is_empty() {
        return Err(ApiError::BadRequest("items must not be empty".into()));
    }
    if request.items.len() > 100 {
        return Err(ApiError::BadRequest(
            "bulk issuance accepts at most 100 items per request".into(),
        ));
    }

    let mut issued = Vec::new();
    let mut errors = Vec::new();
    for (index, item) in request.items.into_iter().enumerate() {
        match issue_one(&state, item).await {
            Ok(credential) => issued.push(credential),
            Err(error) => errors.push(BulkIssueError {
                index,
                error: error.message().to_string(),
            }),
        }
    }

    Ok(Json(BulkIssueResponse { issued, errors }))
}

async fn issue_one(
    state: &AppState,
    request: IssueRequest,
) -> Result<IssuedCredentialResponse, ApiError> {
    validate_uuid(&request.issuer_id)?;
    validate_uuid(&request.schema_id)?;
    if request.subject_ref.trim().is_empty() {
        return Err(ApiError::BadRequest("subject_ref is required".into()));
    }

    let issuer = sqlx::query(
        "SELECT i.status, k.id::text AS key_id, k.signing_seed_hex
         FROM issuers i
         LEFT JOIN LATERAL (
             SELECT id, signing_seed_hex
             FROM issuer_keys
             WHERE issuer_id = i.id AND status = 'active'
             LIMIT 1
         ) k ON true
         WHERE i.id = $1::uuid",
    )
    .bind(&request.issuer_id)
    .fetch_one(&state.pool)
    .await?;
    let issuer_status: String = issuer.get("status");
    if issuer_status != "trusted" {
        return Err(ApiError::Conflict("issuer is not trusted".into()));
    }
    let key_id: String = issuer
        .get::<Option<String>, _>("key_id")
        .ok_or_else(|| ApiError::Conflict("issuer has no active signing key".into()))?;
    let seed_hex: String = issuer
        .get::<Option<String>, _>("signing_seed_hex")
        .ok_or_else(|| ApiError::Conflict("issuer has no active signing key".into()))?;

    let schema_name: String = sqlx::query_scalar(
        "SELECT name FROM credential_schemas WHERE id = $1::uuid AND issuer_id = $2::uuid",
    )
    .bind(&request.schema_id)
    .bind(&request.issuer_id)
    .fetch_one(&state.pool)
    .await?;

    if let Some(idempotency_key) = request.idempotency_key.as_deref()
        && let Some(existing_id) = sqlx::query_scalar::<_, String>(
            "SELECT id::text FROM credentials
             WHERE issuer_id = $1::uuid AND idempotency_key = $2",
        )
        .bind(&request.issuer_id)
        .bind(idempotency_key)
        .fetch_optional(&state.pool)
        .await?
    {
        return load_credential_response(state, &existing_id).await;
    }

    let credential_id = verifier_core::new_credential_id();
    let claims = CredentialClaims {
        credential_id: credential_id.clone(),
        issuer: request.issuer_id.clone(),
        subject: request.subject_ref.clone(),
        credential_type: schema_name.clone(),
        claims: request.claims.clone(),
        key_id: Some(key_id.clone()),
    };
    let signing_key = verifier_core::signing_key_from_seed_hex(&seed_hex)?;
    let signed = verifier_core::sign_claims(&signing_key, &claims)?;
    let payload = serde_json::to_vec(&signed).map_err(|error| {
        tracing::error!(%error, "serialize signed credential");
        ApiError::Internal
    })?;
    let payload_hash = verifier_core::sha256_hex(&payload);
    let leaf_hash = hex::encode(verifier_core::leaf_hash(&payload));

    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        "INSERT INTO credentials
            (id, issuer_id, schema_id, subject_ref, claims, signature_hex, status,
             idempotency_key, key_id)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, 'active', $7, $8::uuid)
         RETURNING issued_at::text",
    )
    .bind(&credential_id)
    .bind(&request.issuer_id)
    .bind(&request.schema_id)
    .bind(&request.subject_ref)
    .bind(&request.claims)
    .bind(&signed.signature_hex)
    .bind(&request.idempotency_key)
    .bind(&key_id)
    .fetch_one(&mut *tx)
    .await?;
    let issued_at: String = row.get("issued_at");

    sqlx::query(
        "INSERT INTO transparency_log (leaf_hash, payload_hash, event_type, credential_id)
         VALUES ($1, $2, 'issued', $3::uuid)",
    )
    .bind(&leaf_hash)
    .bind(&payload_hash)
    .bind(&credential_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(IssuedCredentialResponse {
        id: credential_id,
        issuer_id: request.issuer_id,
        schema_id: request.schema_id,
        subject_ref: request.subject_ref,
        credential_type: schema_name,
        status: "active".into(),
        key_id: Some(key_id),
        claims: request.claims,
        signed_credential: signed,
        share_url: format!("{}/api/verify/{}", state.base_url, claims.credential_id),
        issued_at,
    })
}

async fn get_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<IssuedCredentialResponse>, ApiError> {
    validate_uuid(&id)?;
    Ok(Json(load_credential_response(&state, &id).await?))
}

async fn load_credential_response(
    state: &AppState,
    id: &str,
) -> Result<IssuedCredentialResponse, ApiError> {
    let row = sqlx::query(
        "SELECT c.id::text, c.issuer_id::text, c.schema_id::text, c.subject_ref,
                c.claims, c.signature_hex, c.status, c.issued_at::text,
                c.key_id::text AS key_id, s.name AS schema_name
         FROM credentials c
         JOIN credential_schemas s ON s.id = c.schema_id
         WHERE c.id = $1::uuid",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    let credential_id: String = row.get("id");
    let issuer_id: String = row.get("issuer_id");
    let schema_id: String = row.get("schema_id");
    let subject_ref: String = row.get("subject_ref");
    let claims: Value = row.get("claims");
    let signature_hex: String = row.get("signature_hex");
    let status: String = row.get("status");
    let issued_at: String = row.get("issued_at");
    let schema_name: String = row.get("schema_name");
    let key_id: Option<String> = row.get("key_id");

    let signed = SignedCredential {
        claims: CredentialClaims {
            credential_id: credential_id.clone(),
            issuer: issuer_id.clone(),
            subject: subject_ref.clone(),
            credential_type: schema_name.clone(),
            claims: claims.clone(),
            key_id: key_id.clone(),
        },
        signature_hex,
    };

    Ok(IssuedCredentialResponse {
        id: credential_id,
        issuer_id,
        schema_id,
        subject_ref,
        credential_type: schema_name,
        status,
        key_id,
        claims,
        signed_credential: signed,
        share_url: format!(
            "{}/api/verify/{}",
            state.base_url,
            row.get::<String, _>("id")
        ),
        issued_at,
    })
}

async fn credential_qr(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    validate_uuid(&id)?;
    let credential = load_credential_response(&state, &id).await?;
    let qr = QrCode::encode_text(&credential.share_url, QrCodeEcc::Medium).map_err(|error| {
        tracing::error!(%error, "encode qr");
        ApiError::Internal
    })?;
    let svg = render_qr_svg(&qr, 4);

    Ok(([(header::CONTENT_TYPE, "image/svg+xml")], svg))
}

fn render_qr_svg(qr: &QrCode, border: i32) -> String {
    let size = qr.size();
    let dimension = size + border * 2;
    let mut path = String::new();
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                path.push_str(&format!("M{},{}h1v1h-1z", x + border, y + border));
            }
        }
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dimension} {dimension}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#ffffff"/><path d="{path}" fill="#000000"/></svg>"##
    )
}

async fn credential_proof(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ProofResponse>, ApiError> {
    validate_uuid(&id)?;
    let leaf_hash: String = sqlx::query_scalar(
        "SELECT leaf_hash FROM transparency_log
         WHERE credential_id = $1::uuid AND event_type = 'issued'
         ORDER BY id LIMIT 1",
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;

    let rows = sqlx::query("SELECT leaf_hash FROM transparency_log ORDER BY id")
        .fetch_all(&state.pool)
        .await?;
    let mut leaves = Vec::with_capacity(rows.len());
    let mut index = None;
    for (position, row) in rows.iter().enumerate() {
        let hash: String = row.get("leaf_hash");
        if hash == leaf_hash {
            index = Some(position);
        }
        leaves.push(decode_hash(&hash)?);
    }

    let index = index.ok_or_else(|| ApiError::NotFound("log leaf not found".into()))?;
    let proof = verifier_core::inclusion_proof(&leaves, index).ok_or(ApiError::Internal)?;
    let root = verifier_core::merkle_root(&leaves);

    Ok(Json(ProofResponse {
        credential_id: id,
        leaf_hash,
        leaf_index: index,
        tree_size: leaves.len(),
        root_hash: hex::encode(root),
        audit_path: proof.iter().map(hex::encode).collect(),
    }))
}

async fn log_root(
    State(state): State<AppState>,
    Query(query): Query<LogRootQuery>,
) -> Result<Json<LogRootResponse>, ApiError> {
    let leaves = load_log_leaves(&state).await?;
    let tree_size = query.tree_size.unwrap_or(leaves.len());
    if tree_size > leaves.len() {
        return Err(ApiError::BadRequest(
            "tree_size exceeds the current log size".into(),
        ));
    }

    Ok(Json(LogRootResponse {
        tree_size,
        root_hash: hex::encode(verifier_core::merkle_root(&leaves[..tree_size])),
    }))
}

async fn log_consistency(
    State(state): State<AppState>,
    Query(query): Query<LogConsistencyQuery>,
) -> Result<Json<LogConsistencyResponse>, ApiError> {
    let leaves = load_log_leaves(&state).await?;
    let second_size = query.second_size.unwrap_or(leaves.len());
    if query.first_size == 0 || query.first_size > second_size || second_size > leaves.len() {
        return Err(ApiError::BadRequest(
            "require 1 <= first_size <= second_size <= current log size".into(),
        ));
    }

    let proof = verifier_core::consistency_proof(&leaves[..second_size], query.first_size)
        .ok_or_else(|| ApiError::BadRequest("cannot build consistency proof".into()))?;

    Ok(Json(LogConsistencyResponse {
        first_size: query.first_size,
        second_size,
        first_root: hex::encode(verifier_core::merkle_root(&leaves[..query.first_size])),
        second_root: hex::encode(verifier_core::merkle_root(&leaves[..second_size])),
        proof: proof.iter().map(hex::encode).collect(),
    }))
}

async fn load_log_leaves(state: &AppState) -> Result<Vec<[u8; 32]>, ApiError> {
    let rows = sqlx::query("SELECT leaf_hash FROM transparency_log ORDER BY id")
        .fetch_all(&state.pool)
        .await?;
    rows.iter()
        .map(|row| decode_hash(&row.get::<String, _>("leaf_hash")))
        .collect()
}

async fn verify_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<VerifyResponse>, ApiError> {
    validate_uuid(&id)?;
    let row = sqlx::query(
        "SELECT c.id::text, c.issuer_id::text, c.subject_ref, c.claims, c.signature_hex,
                c.status, c.issued_at::text, c.key_id::text AS key_id,
                s.name AS schema_name, i.name AS issuer_name, i.status AS issuer_status,
                i.signing_seed_hex AS legacy_seed_hex,
                k.signing_seed_hex AS key_seed_hex, k.status AS key_status,
                r.reason AS revocation_reason, r.revoked_at::text AS revoked_at,
                (SELECT tl.leaf_hash FROM transparency_log tl
                 WHERE tl.credential_id = c.id AND tl.event_type = 'issued'
                 ORDER BY tl.id LIMIT 1) AS log_leaf_hash
         FROM credentials c
         JOIN issuers i ON i.id = c.issuer_id
         JOIN credential_schemas s ON s.id = c.schema_id
         LEFT JOIN issuer_keys k ON k.id = c.key_id
         LEFT JOIN revocation_entries r ON r.credential_id = c.id
         WHERE c.id = $1::uuid",
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;

    let credential_id: String = row.get("id");
    let issuer_id: String = row.get("issuer_id");
    let subject_ref: String = row.get("subject_ref");
    let claims: Value = row.get("claims");
    let signature_hex: String = row.get("signature_hex");
    let credential_status: String = row.get("status");
    let issued_at: String = row.get("issued_at");
    let schema_name: String = row.get("schema_name");
    let issuer_name: String = row.get("issuer_name");
    let issuer_status: String = row.get("issuer_status");
    let key_id: Option<String> = row.get("key_id");
    let key_seed_hex: Option<String> = row.get("key_seed_hex");
    let key_status: Option<String> = row.get("key_status");
    let legacy_seed_hex: String = row.get("legacy_seed_hex");
    let revocation_reason: Option<String> = row.get("revocation_reason");
    let revoked_at: Option<String> = row.get("revoked_at");
    let log_leaf_hash: Option<String> = row.get("log_leaf_hash");

    let seed_hex = match (&key_id, key_seed_hex) {
        (Some(_), Some(seed)) => seed,
        (Some(_), None) => return Err(ApiError::Internal),
        (None, _) => legacy_seed_hex,
    };
    let effective_key_status = if key_id.is_some() {
        key_status
    } else {
        Some("legacy".into())
    };

    let signed = SignedCredential {
        claims: CredentialClaims {
            credential_id: credential_id.clone(),
            issuer: issuer_id.clone(),
            subject: subject_ref.clone(),
            credential_type: schema_name.clone(),
            claims: claims.clone(),
            key_id: key_id.clone(),
        },
        signature_hex,
    };
    let signing_key = verifier_core::signing_key_from_seed_hex(&seed_hex)?;
    let signature_valid =
        verifier_core::verify_signed_credential(&signing_key.verifying_key(), &signed).is_ok();
    let issuer_trusted = issuer_status == "trusted";
    let key_revoked = effective_key_status.as_deref() == Some("revoked");
    let active = credential_status == "active";
    let valid = signature_valid && issuer_trusted && active && !key_revoked;
    let status = if !signature_valid {
        "invalid_signature"
    } else if key_revoked {
        "issuer_key_revoked"
    } else if !issuer_trusted {
        "issuer_untrusted"
    } else if !active {
        "revoked"
    } else {
        "valid"
    };

    Ok(Json(VerifyResponse {
        valid,
        status: status.into(),
        credential_id,
        issuer_id,
        issuer_name,
        subject_ref,
        credential_type: schema_name,
        claims,
        issued_at,
        revoked_at,
        revocation_reason,
        key_id,
        key_status: effective_key_status,
        signature_valid,
        issuer_trusted,
        log_leaf_hash,
    }))
}

async fn revoke_credential(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<RevokeRequest>,
) -> Result<Json<RevocationResponse>, ApiError> {
    validate_uuid(&id)?;
    if request.reason.trim().is_empty() {
        return Err(ApiError::BadRequest("reason is required".into()));
    }

    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT status FROM credentials WHERE id = $1::uuid FOR UPDATE")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
    let status: String = row.get("status");

    if status == "revoked" {
        tx.commit().await?;
        return Ok(Json(load_revocation(&state, &id).await?));
    }
    if status != "active" {
        return Err(ApiError::Conflict(
            "credential cannot be revoked in its current state".into(),
        ));
    }

    sqlx::query("UPDATE credentials SET status = 'revoked' WHERE id = $1::uuid")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    let revoked_at: String = sqlx::query_scalar(
        "INSERT INTO revocation_entries (credential_id, reason)
         VALUES ($1::uuid, $2)
         RETURNING revoked_at::text",
    )
    .bind(&id)
    .bind(request.reason.trim())
    .fetch_one(&mut *tx)
    .await?;

    let payload = serde_json::to_vec(&json!({
        "credential_id": id,
        "reason": request.reason.trim(),
        "revoked_at": revoked_at,
    }))
    .map_err(|error| {
        tracing::error!(%error, "serialize revocation event");
        ApiError::Internal
    })?;
    let leaf_hash = hex::encode(verifier_core::leaf_hash(&payload));
    let payload_hash = verifier_core::sha256_hex(&payload);
    sqlx::query(
        "INSERT INTO transparency_log (leaf_hash, payload_hash, event_type, credential_id)
         VALUES ($1, $2, 'revoked', $3::uuid)",
    )
    .bind(&leaf_hash)
    .bind(&payload_hash)
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(RevocationResponse {
        credential_id: id,
        status: "revoked".into(),
        reason: request.reason.trim().to_string(),
        revoked_at,
    }))
}

async fn load_revocation(state: &AppState, id: &str) -> Result<RevocationResponse, ApiError> {
    let row = sqlx::query(
        "SELECT credential_id::text, reason, revoked_at::text
         FROM revocation_entries WHERE credential_id = $1::uuid",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    Ok(RevocationResponse {
        credential_id: row.get("credential_id"),
        status: "revoked".into(),
        reason: row.get("reason"),
        revoked_at: row.get("revoked_at"),
    })
}

async fn status_list(State(state): State<AppState>) -> Result<Json<StatusListResponse>, ApiError> {
    let active = sqlx::query_scalar::<_, String>(
        "SELECT id::text FROM credentials WHERE status = 'active' ORDER BY issued_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    let rows = sqlx::query(
        "SELECT credential_id::text, reason, revoked_at::text
         FROM revocation_entries ORDER BY revoked_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;
    let revoked = rows
        .iter()
        .map(|row| StatusListEntry {
            credential_id: row.get("credential_id"),
            reason: row.get("reason"),
            revoked_at: row.get("revoked_at"),
        })
        .collect();

    let generated_at: String = sqlx::query_scalar("SELECT now()::text")
        .fetch_one(&state.pool)
        .await?;

    Ok(Json(StatusListResponse {
        generated_at,
        active,
        revoked,
    }))
}

async fn fetch_issuer_row(state: &AppState, id: &str) -> Result<sqlx::postgres::PgRow, ApiError> {
    Ok(sqlx::query(
        "SELECT i.id::text, i.name, i.status, i.created_at::text,
                k.id::text AS key_id, k.signing_seed_hex AS key_seed_hex
         FROM issuers i
         LEFT JOIN LATERAL (
             SELECT id, signing_seed_hex
             FROM issuer_keys
             WHERE issuer_id = i.id AND status = 'active'
             LIMIT 1
         ) k ON true
         WHERE i.id = $1::uuid",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?)
}

fn row_to_issuer(row: &sqlx::postgres::PgRow) -> Result<IssuerResponse, ApiError> {
    let key_id: Option<String> = row.get("key_id");
    let key_seed_hex: Option<String> = row.get("key_seed_hex");
    let public_key_hex = match key_seed_hex {
        Some(seed_hex) => {
            let signing_key = verifier_core::signing_key_from_seed_hex(&seed_hex)?;
            Some(verifier_core::verifying_key_hex(
                &signing_key.verifying_key(),
            ))
        }
        None => None,
    };

    Ok(IssuerResponse {
        id: row.get("id"),
        name: row.get("name"),
        status: row.get("status"),
        key_id,
        public_key_hex,
        created_at: row.get("created_at"),
    })
}

fn row_to_key(row: &sqlx::postgres::PgRow) -> Result<IssuerKeyResponse, ApiError> {
    let seed_hex: String = row.get("signing_seed_hex");
    let signing_key = verifier_core::signing_key_from_seed_hex(&seed_hex)?;

    Ok(IssuerKeyResponse {
        key_id: row.get("key_id"),
        issuer_id: row.get("issuer_id"),
        public_key_hex: verifier_core::verifying_key_hex(&signing_key.verifying_key()),
        status: row.get("status"),
        created_at: row.get("created_at"),
        retired_at: row.get("retired_at"),
        revoked_at: row.get("revoked_at"),
        revocation_reason: row.get("revocation_reason"),
    })
}

fn row_to_schema(row: &sqlx::postgres::PgRow) -> SchemaResponse {
    SchemaResponse {
        id: row.get("id"),
        issuer_id: row.get("issuer_id"),
        name: row.get("name"),
        version: row.get("version"),
        schema_json: row.get("schema_json"),
        created_at: row.get("created_at"),
    }
}

fn validate_uuid(value: &str) -> Result<(), ApiError> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| ApiError::BadRequest("invalid uuid".into()))
}

fn decode_hash(value: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(value).map_err(|error| {
        tracing::error!(%error, "decode hash");
        ApiError::Internal
    })?;
    bytes.try_into().map_err(|_| ApiError::Internal)
}
