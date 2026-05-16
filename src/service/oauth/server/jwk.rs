use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as b64};
use p256::{
	ecdsa::SigningKey,
	elliptic_curve::sec1::ToEncodedPoint,
	pkcs8::DecodePrivateKey,
};
use serde_json::{Value as JsonValue, json};
use tuwunel_core::{Result, err};

impl super::Server {
	#[inline]
	#[must_use]
	pub fn jwks(&self) -> JsonValue {
		json!({
			"keys": [self.jwk.clone()],
		})
	}
}

pub(super) fn init_jwk(key_der: &[u8], key_id: &str) -> Result<JsonValue> {
	let signing_key = SigningKey::from_pkcs8_der(key_der)
		.map_err(|e| err!(error!("Failed to load ECDSA key: {e}")))?;
	let public_key = signing_key.verifying_key();
	let public_bytes = public_key.to_encoded_point(false);
	let x = public_bytes
		.x()
		.ok_or_else(|| err!(error!("Failed to encode ECDSA public key x coordinate")))?;
	let y = public_bytes
		.y()
		.ok_or_else(|| err!(error!("Failed to encode ECDSA public key y coordinate")))?;

	Ok(json!({
		"kty": "EC",
		"crv": "P-256",
		"use": "sig",
		"alg": "ES256",
		"kid": key_id,
		"x": b64.encode(x),
		"y": b64.encode(y),
	}))
}
