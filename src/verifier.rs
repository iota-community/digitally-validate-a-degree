use anyhow::Result;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Object;
use identity_iota::credential::{
    DecodedJwtCredential, DecodedJwtPresentation, FailFast, Jwt, JwtCredentialValidationOptions,
    JwtCredentialValidator, JwtPresentationValidationOptions, JwtPresentationValidator,
    JwtPresentationValidatorUtils, SubjectHolderRelationship,
};
use identity_iota::did::CoreDID;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;
use shared_utils::get_read_only_client;
use std::collections::HashMap;
use identity_iota::did::DID;

#[tokio::main]
async fn main() -> Result<()> {
    // Get VP JWT from CLI args
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin verifier <VP_JWT>");
        return Err(anyhow::anyhow!("Missing VP JWT argument."));
    }
    let vp_jwt_str = &args[1];
    let vp_jwt = Jwt::new(vp_jwt_str.clone());

    println!("✅ Loaded VP JWT");

    // Challenge must exactly match what holder used
    let challenge = "challenge-123";
    println!("🔍 Using challenge: {}", challenge);
    let presentation_verifier_options = JwsVerificationOptions::default().nonce(challenge.to_owned());

    // Build resolver and attach IOTA client
    let verifier_client = get_read_only_client().await?;
    let mut resolver: Resolver<IotaDocument> = Resolver::new();
    resolver.attach_iota_handler(verifier_client);

    // Resolve holder DID
    let holder_did: CoreDID = JwtPresentationValidatorUtils::extract_holder(&vp_jwt)?;
    println!("🔑 Extracted holder DID from VP: {}", holder_did);
    let holder_doc: IotaDocument = resolver.resolve(&holder_did).await?;
    println!("✅ Resolved holder DID from network: {}", holder_doc.id());

    // Validate VP
    let vp_validation_options = JwtPresentationValidationOptions::default()
        .presentation_verifier_options(presentation_verifier_options);

    let decoded_vp: DecodedJwtPresentation<Jwt> = JwtPresentationValidator::with_signature_verifier(EdDSAJwsVerifier::default())
        .validate(&vp_jwt, &holder_doc, &vp_validation_options)?;

    println!("✅ VP JWT verified successfully");
    println!("✅ Holder DID matches: {}", decoded_vp.presentation.holder);

    // Extract credentials
    let jwt_credentials: &Vec<Jwt> = &decoded_vp.presentation.verifiable_credential;
    println!("📦 VP contains {} credential(s)", jwt_credentials.len());

    // Resolve issuers
    let issuers: Vec<CoreDID> = jwt_credentials
        .iter()
        .map(|jwt| identity_iota::credential::JwtCredentialValidatorUtils::extract_issuer_from_jwt(jwt))
        .collect::<Result<Vec<CoreDID>, _>>()?;
    println!("🔑 Issuer DIDs: {:?}", issuers);

    let issuers_documents: HashMap<CoreDID, IotaDocument> = resolver.resolve_multiple(&issuers).await?;

    // Validate each credential
    let credential_validator = JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());
    let credential_validation_options = JwtCredentialValidationOptions::default()
        .subject_holder_relationship(holder_did.to_url().into(), SubjectHolderRelationship::AlwaysSubject);

    for (index, jwt_vc) in jwt_credentials.iter().enumerate() {
        let issuer_doc = &issuers_documents[&issuers[index]];
        let decoded_credential: DecodedJwtCredential<Object> = credential_validator
            .validate::<_, Object>(jwt_vc, issuer_doc, &credential_validation_options, FailFast::FirstError)?;

        let subject_id = decoded_credential
            .credential
            .credential_subject
            .first()
            .and_then(|subj| subj.id.as_ref())
            .map(|id| id.as_str())
            .unwrap_or("unknown");

        println!(
            "✅ Credential [{}]: verified successfully, subject: {}",
            index + 1,
            subject_id
        );
    }

    println!("\n🎉 All credentials in the VP are valid!");
    Ok(())
}
