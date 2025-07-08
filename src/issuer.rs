// issuer.rs
use anyhow::Result;
use identity_iota::core::{FromJson, ToJson, Url};
use identity_iota::credential::{Credential, CredentialBuilder, Subject};
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_storage::{JwkDocumentExt, JwsSignatureOptions};
use shared_utils::{create_did_document, get_funded_client, get_stronghold_storage};
use std::fs;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let issuer_storage = get_stronghold_storage(Some(PathBuf::from("./issuer.stronghold")))?;
    let issuer_client = get_funded_client(&issuer_storage).await?;

    // Create issuer DID if not exists
    let issuer_doc_file = "./issuer_doc.json";
    let issuer_fragment_file = "./issuer_fragment.txt";
    let (issuer_doc, issuer_fragment) = if !PathBuf::from(issuer_doc_file).exists() {
        let (doc, frag) = create_did_document(&issuer_client, &issuer_storage).await?;
        fs::write(issuer_doc_file, doc.to_json()?)?;
        fs::write(issuer_fragment_file, &frag)?;
        println!("✅ Created issuer DID: {}", doc.id());
        (doc, frag)
    } else {
        let json = fs::read_to_string(issuer_doc_file)?;
        let doc = IotaDocument::from_json(&json)?;
        let frag = fs::read_to_string(issuer_fragment_file)?.trim().to_string();
        (doc, frag)
    };

    // Load holder DID created by holder
    let holder_doc_json = fs::read_to_string("./holder_doc.json")?;
    let holder_doc = IotaDocument::from_json(&holder_doc_json)?;
    println!("✅ Loaded holder DID: {}", holder_doc.id());

    // Build VC
    let subject = Subject::from_json_value(serde_json::json!({
        "id": holder_doc.id().as_str(),
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
    fs::write("vc.jwt", credential_jwt.as_str())?;
    println!("✅ Saved VC to vc.jwt");
    Ok(())
}
