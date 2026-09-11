use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};

use crate::error::ApiError;

const AES_GCM_IV_BYTES: usize = 12;
const AES_GCM_TAG_BYTES: usize = 16;
const AES_256_KEY_BYTES: usize = 32;

pub(crate) const MIN_ENVELOPE_BYTES: usize = AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES;
pub(crate) const WRAPPED_CHAT_KEY_BYTES: usize = MIN_ENVELOPE_BYTES + AES_256_KEY_BYTES;

pub(crate) fn decode_envelope(
    field: &str,
    encoded: &str,
    minimum_bytes: usize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ApiError> {
    let maximum_encoded_bytes = maximum_bytes.div_ceil(3) * 4;
    if encoded.is_empty() || encoded.len() > maximum_encoded_bytes {
        return Err(ApiError::BadRequest(format!(
            "{field} exceeds the encoded size limit"
        )));
    }
    let decoded = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .map_err(|_| ApiError::BadRequest(format!("{field} must be standard Base64")))?;
    if decoded.len() < minimum_bytes || decoded.len() > maximum_bytes {
        return Err(ApiError::BadRequest(format!(
            "{field} must decode to {minimum_bytes}..{maximum_bytes} bytes"
        )));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_aes_gcm_envelope() {
        let envelope = STANDARD.encode(vec![0_u8; MIN_ENVELOPE_BYTES]);
        assert_eq!(
            decode_envelope("ciphertext", &envelope, MIN_ENVELOPE_BYTES, 1024)
                .unwrap()
                .len(),
            MIN_ENVELOPE_BYTES
        );
    }

    #[test]
    fn rejects_short_or_malformed_envelopes() {
        let short = STANDARD.encode(vec![0_u8; MIN_ENVELOPE_BYTES - 1]);
        assert!(decode_envelope("ciphertext", &short, MIN_ENVELOPE_BYTES, 1024).is_err());
        assert!(decode_envelope("ciphertext", "not base64!", MIN_ENVELOPE_BYTES, 1024).is_err());
    }
}
