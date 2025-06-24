use std::collections::HashMap;

// use crate::utils::*;
use utils;
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

    pub async fn create_presentation(vc_jwt: String) -> anyhow::Result<()> {

    // create new holder account with did document
    let holder_storage = get_memstorage()?;
    let holder_identity_client = get_funded_client(&holder_storage).await?;
    let (holder_document, holder_vm_fragment) = create_did_document(&holder_identity_client, &holder_storage).await?;


    // Create an unsigned Presentation from the previously issued Verifiable Credential.
    let presentation: Presentation<Jwt> =
    PresentationBuilder::new(holder_document.id().to_url().into(), Default::default())
    .credential(vc_jwt.clone())
    .build()?;

    // Create a JWT verifiable presentation using the holder's verification method
    // and include the requested challenge and expiry timestamp.
    let presentation_jwt: Jwt = holder_document
    .create_presentation_jwt(
        &presentation,
        &holder_storage,
        &holder_vm_fragment,
        &JwsSignatureOptions::default().nonce(challenge.to_owned()),
        &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await?;

    // ===========================================================================
    // Holder sends a verifiable presentation to the verifier.
    // ===========================================================================
    println!("Sending presentation (as JWT) to the verifier: {presentation_jwt:#}");

    ok(())
}