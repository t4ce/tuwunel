use p256::{
	ecdsa::SigningKey as EcdsaSigningKey,
	elliptic_curve::rand_core::OsRng,
	pkcs8::EncodePrivateKey,
};
use serde::{Deserialize, Serialize};
use tuwunel_core::{Result, at, err, info, utils};
use tuwunel_database::{Cbor, Deserialized};

use super::Data;

#[derive(Deserialize, Serialize)]
pub(super) struct SigningKey {
	pub(super) key_id: String,
	pub(super) key_der: Vec<u8>,
}

const SIGNING_KEY_DB_KEY: &str = "oidc_signing_key";

pub(super) fn init_signing_key(db: &Data) -> Result<SigningKey> {
	if let Ok(signing_key_data) = db
		.oidc_signingkey
		.get_blocking(SIGNING_KEY_DB_KEY)
		.and_then(|val| val.deserialized::<Cbor<SigningKey>>())
		.map(at!(0))
	{
		info!(
			key_id = ?signing_key_data.key_id,
			"Loaded existing OIDC signing key",
		);

		return Ok(signing_key_data);
	}

	let signing_key_data = generate_signing_key()?;

	db.oidc_signingkey
		.raw_put(SIGNING_KEY_DB_KEY, Cbor(&signing_key_data));

	info!(
		key_id = ?signing_key_data.key_id,
		"Generated new OIDC signing key",
	);

	Ok(signing_key_data)
}

fn generate_signing_key() -> Result<SigningKey> {
	let key_id = utils::random_string(16);
	let signing_key = EcdsaSigningKey::random(&mut OsRng);
	let pkcs8 = signing_key
		.to_pkcs8_der()
		.map_err(|e| err!(error!("Failed to generate ECDSA key: {e}")))?;

	Ok(SigningKey { key_der: pkcs8.as_bytes().to_vec(), key_id })
}
