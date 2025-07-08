// holder.rs
use anyhow::Result;
use identity_iota::core::{Duration, FromJson, Timestamp, ToJson};
use identity_iota::credential::{Jwt, JwtPresentationOptions, Presentation, PresentationBuilder};
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_storage::{JwkDocumentExt, JwsSignatureOptions};
use shared_utils::{create_did_document, get_stronghold_storage, get_funded_client};
use std::fs;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    // Use a fixed stronghold file so keys survive
    let holder_storage = get_stronghold_storage(Some(PathBuf::from("./holder.stronghold")))?;

    // STEP 1: If holder DID does NOT exist, create it & save.
    let did_file = "./holder_doc.json";
    let fragment_file = "./holder_fragment.txt";

    if !PathBuf::from(did_file).exists() {
        let holder_client = get_funded_client(&holder_storage).await?;
        let (holder_doc, holder_fragment) = create_did_document(&holder_client, &holder_storage).await?;

        fs::write(did_file, holder_doc.to_json()?)?;
        fs::write(fragment_file, &holder_fragment)?;
        println!("Created & saved holder DID: {}", holder_doc.id());
        println!("Fragment: {}", holder_fragment);
        return Ok(()); // stop here, next step: issuer issues VC
    }

    // STEP 2: Build VP using VC passed as argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin holder <VC_JWT>");
        return Err(anyhow::anyhow!("Missing VC JWT argument."));
    }
    let vc_jwt = &args[1];

    let holder_doc_json = fs::read_to_string(did_file)?;
    let holder_doc = IotaDocument::from_json(&holder_doc_json)?;
    let holder_fragment = fs::read_to_string(fragment_file)?.trim().to_string();

    let presentation: Presentation<Jwt> = PresentationBuilder::new(holder_doc.id().to_url().into(), Default::default())
        .credential(Jwt::new(vc_jwt.clone()))
        .build()?;
    println!("✅ Built Presentation");

    let challenge = "challenge-123";
    let expires = Timestamp::now_utc().checked_add(Duration::minutes(10)).unwrap();

    let vp_jwt: Jwt = holder_doc
        .create_presentation_jwt(
            &presentation,
            &holder_storage,
            &holder_fragment,
            &JwsSignatureOptions::default().nonce(challenge.to_owned()),
            &JwtPresentationOptions::default().expiration_date(expires),
        )
        .await?;
    println!("✅ Created VP JWT:\n{}", vp_jwt.as_str());
    fs::write("vp.jwt", vp_jwt.as_str())?;
    Ok(())
}
