// holder.rs
use anyhow::Result;
use identity_iota::core::{Duration, FromJson, Object, Timestamp, ToJson};
use identity_iota::credential::{Jwt, JwtPresentationOptions, PresentationBuilder};
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_storage::{JwkDocumentExt, JwkMemStore, JwkStorage, JwsSignatureOptions};
use shared_utils::create_did_document;
use shared_utils::get_memstorage;
use shared_utils::get_funded_client;
use std::fs;









#[tokio::main]
async fn main() -> Result<()> {
    // === Accept VC JWT from CLI argument ===
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin holder <VC_JWT>");
        return Err(anyhow::anyhow!("Missing VC JWT argument."));
    }
    let vc_jwt = &args[1];
    println!("✅ Received VC JWT: {}", vc_jwt);

    // === Load holder DID document ===
    let holder_doc_json = fs::read_to_string("holder_doc.json")?;
    let holder_doc = IotaDocument::from_json(&holder_doc_json)?;
    println!("✅ Loaded holder DID: {}", holder_doc.id());

    // === Create a new key for the holder ===
    let holder_storage = get_memstorage().await?;

    let jwk_output = holder_storage
        .key_storage()
        .generate(identity_storage::KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
        .await?;

    let holder_key_id = jwk_output.key_id;
    let holder_jwk_public = jwk_output.jwk;

    fs::write("holder_keyid.txt", holder_key_id.as_str())?;
    fs::write("holder_jwk_public.json", holder_jwk_public.to_json()?)?;
    println!("✅ Generated holder key and saved public JWK and key ID");

    // === Build the Verifiable Presentation ===
    let challenge = "475a7984-1bb5-4c4c-a56f-822bccd46440";
    let expires = Timestamp::now_utc()
        .checked_add(Duration::minutes(10))
        .expect("Failed to set expiration timestamp");

    let presentation = PresentationBuilder::new(holder_doc.id().to_url().into(), Object::default())
        .credential(vc_jwt.to_owned())
        .build()?;

let vp_jwt: Jwt = holder_doc
    .create_presentation_jwt(
        &presentation,
        &holder_storage,
        holder_key_id.as_str(), // ✅ FIXED
        &JwsSignatureOptions::default().nonce(challenge.to_owned()),
        &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await?;

    println!("✅ Created VP JWT: {}", vp_jwt.as_str());
    fs::write("vp.jwt", vp_jwt.as_str())?;
    println!("✅ Saved VP JWT to vp.jwt");

    Ok(())
}
