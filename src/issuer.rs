//! cargo run --release --example 6_create_vp

use std::collections::HashMap;

use crate::utils;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Object;
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::DecodedJwtPresentation;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::JwtPresentationValidationOptions;
use identity_iota::credential::JwtPresentationValidator;
use identity_iota::credential::JwtPresentationValidatorUtils;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::did::CoreDID;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;

use identity_iota::core::json;
use identity_iota::core::Duration;
use identity_iota::core::FromJson;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::FailFast;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::Subject;
use identity_iota::credential::SubjectHolderRelationship;
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ===========================================================================
    // Step 1: Create identity for the issuer.
    // ===========================================================================

    // create new issuer account with did document
    let issuer_storage = get_memstorage()?;
    let issuer_identity_client = get_funded_client(&issuer_storage).await?;
    let (issuer_document, issuer_vm_fragment) =
        create_did_document(&issuer_identity_client, &issuer_storage).await?;

    // ===========================================================================
    // Step 2: Issuer creates and signs a Verifiable Credential.
    // ===========================================================================

    // Create a credential subject indicating the degree earned by Alice.
    let subject: Subject = Subject::from_json_value(json!({
      "id": holder_document.id().as_str(),
      "name": "Alice",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts",
      },
      "GPA": "4.0",
    }))?;

    // Build credential using subject above and issuer.
    let credential: Credential = CredentialBuilder::default()
        .id(Url::parse("https://example.edu/credentials/3732")?)
        .issuer(Url::parse(issuer_document.id().as_str())?)
        .type_("UniversityDegreeCredential")
        .subject(subject)
        .build()?;

    let credential_jwt: Jwt = issuer_document
        .create_credential_jwt(
            &credential,
            &issuer_storage,
            &issuer_vm_fragment,
            &JwsSignatureOptions::default(),
            None,
        )
        .await?;

    // Before sending this credential to the holder the issuer wants to validate that some properties
    // of the credential satisfy their expectations.

    // Validate the credential's signature using the issuer's DID Document, the credential's semantic structure,
    // that the issuance date is not in the future and that the expiration date is not in the past:
    JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
        .validate::<_, Object>(
            &credential_jwt,
            &issuer_document,
            &JwtCredentialValidationOptions::default(),
            FailFast::FirstError,
        )
        .unwrap();

    println!("VC successfully validated");

    // ===========================================================================
    // Step 3: Issuer sends the Verifiable Credential to the holder.
    // ===========================================================================
    println!("Sending credential (as JWT) to the holder: {credential:#}");

    Ok(())
}
