use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Multipart, State},
    routing::post,
};

use crate::{AppState, auth::User, error::ApiError, inference::DocumentProcessingError};

const MAX_DOCUMENT_BYTES: usize = 20 * 1024 * 1024;
const MULTIPART_OVERHEAD_BYTES: usize = 128 * 1024;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/v3/documents/process",
        post(process_document).layer(DefaultBodyLimit::max(
            MAX_DOCUMENT_BYTES + MULTIPART_OVERHEAD_BYTES,
        )),
    )
}

async fn process_document(
    State(state): State<Arc<AppState>>,
    _user: User,
    mut multipart: Multipart,
) -> Result<Json<crate::inference::ProcessedDocument>, ApiError> {
    let mut upload = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::BadRequest("invalid document upload".into()))?
    {
        if field.name() != Some("files") || upload.is_some() {
            return Err(ApiError::BadRequest(
                "exactly one document must be uploaded in the files field".into(),
            ));
        }
        let filename = field
            .file_name()
            .map(str::to_owned)
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| ApiError::BadRequest("the document filename is required".into()))?;
        let content_type = document_content_type(&filename).ok_or_else(|| {
            ApiError::BadRequest(
                "supported document formats are PDF, DOCX, PPTX, XLSX, and CSV".into(),
            )
        })?;

        let mut data = Vec::with_capacity(
            field
                .headers()
                .get(axum::http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0)
                .min(MAX_DOCUMENT_BYTES),
        );
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|_| ApiError::BadRequest("invalid document upload".into()))?
        {
            if data.len().saturating_add(chunk.len()) > MAX_DOCUMENT_BYTES {
                return Err(ApiError::BadRequest(
                    "document attachments must be 20 MiB or smaller".into(),
                ));
            }
            data.extend_from_slice(&chunk);
        }
        if data.is_empty() {
            return Err(ApiError::BadRequest("the document is empty".into()));
        }
        upload = Some((filename, content_type.to_owned(), data));
    }

    let (filename, content_type, data) = upload.ok_or_else(|| {
        ApiError::BadRequest("exactly one document must be uploaded in the files field".into())
    })?;
    let _permit = state
        .inference_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Unavailable)?;
    let processed = state
        .inference
        .process_document(filename, content_type, data)
        .await
        .map_err(|error| match error {
            DocumentProcessingError::Rejected => {
                ApiError::BadRequest("the document could not be processed".into())
            }
            DocumentProcessingError::Unavailable => ApiError::Unavailable,
        })?;
    Ok(Json(processed))
}

fn document_content_type(filename: &str) -> Option<&'static str> {
    let filename = filename.to_ascii_lowercase();
    if filename.ends_with(".pdf") {
        Some("application/pdf")
    } else if filename.ends_with(".docx") {
        Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    } else if filename.ends_with(".pptx") {
        Some("application/vnd.openxmlformats-officedocument.presentationml.presentation")
    } else if filename.ends_with(".xlsx") {
        Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    } else if filename.ends_with(".csv") {
        Some("text/csv")
    } else {
        None
    }
}
