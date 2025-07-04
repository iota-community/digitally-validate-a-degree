// issuer.rs
use anyhow::Result;
use identity_iota::credential::{self, *};
use identity_iota::core::{json, FromJson, Object, ToJson, Url};
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_storage::{JwkStorage, JwsSignatureOptions};
// use shared_utils::{create_did_document, get_funded_client, get_memstorage};
use shared_utils::create_did_document;
use shared_utils::get_memstorage;
use shared_utils::get_funded_client;
use std::fs;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_storage::JwkDocumentExt as _;



#[tokio::main]
async fn main() -> Result<()> {
    // === Create issuer identity ===
    let issuer_storage = get_memstorage().await?;
    let issuer_client = get_funded_client(&issuer_storage).await?;
    let (issuer_doc, issuer_fragment) = create_did_document(&issuer_client, &issuer_storage).await?;

    // === Create holder identity (DID only, key generation moved to holder.rs) ===
    let holder_storage_for_did = get_memstorage().await?; // Temporary storage for DID creation
    let holder_client_for_did = get_funded_client(&holder_storage_for_did).await?;
    let (holder_doc, _holder_fragment) = create_did_document(&holder_client_for_did, &holder_storage_for_did).await?;

    // === Save holder DID doc ===
    fs::write("holder_doc.json", holder_doc.to_json()?)?;
    println!("✅ Exported holder DID doc");

    // === Issue VC ===
    let subject = Subject::from_json_value(json!({
        "id": holder_doc.id().as_str(), // Use the holder's public DID
        "name": "Alice",
        "degree": { "type": "BachelorDegree", "name": "Bachelor of Science and Arts" },
        "GPA": "4.0"
    }))?;

    let credential: Credential = CredentialBuilder::default()
        .id(Url::parse("https://example.edu/credentials/3732")?)
        .issuer(Url::parse(issuer_doc.id().as_str())?)
        .type_("UniversityDegreeCredential")
        .subject(subject)
        .build()?;

    let credential_jwt = issuer_doc
        .create_credential_jwt(
            &credential,
            &issuer_storage,
            &issuer_fragment,
            &JwsSignatureOptions::default(),
            None,
        )
        .await?;

    println!("✅ Created VC JWT:\n{}", credential_jwt.as_str());
    Ok(())
}
