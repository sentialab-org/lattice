use lattice_crypto::{encode_key, public_key, sign, sign_domain, verify, verify_domain};
use serde::Serialize;

#[test]
fn authority_signatures_cannot_cross_domains_or_use_legacy_verification() {
    let private = [7; 32];
    let key = encode_key(&public_key(&private));
    let payload = serde_json::json!({"network_id":"test", "revision":1});
    let signature = sign_domain(&private, "lattice/certificate/v1", &payload).unwrap();
    verify_domain(&key, "lattice/certificate/v1", &signature, &payload).unwrap();
    assert!(verify_domain(&key, "lattice/command/v1", &signature, &payload).is_err());
    assert!(verify(&key, &signature, &payload).is_err());
    let legacy = sign(&private, &payload).unwrap();
    verify(&key, &legacy, &payload).unwrap();
    assert!(verify_domain(&key, "lattice/certificate/v1", &legacy, &payload).is_err());
    assert!(
        verify_domain(
            &key,
            "lattice/certificate/v1",
            &signature,
            &serde_json::json!({"network_id":"another-network", "revision":1})
        )
        .is_err()
    );
}

#[test]
fn signed_objects_use_canonical_key_order_independent_of_rust_field_order() {
    #[derive(Serialize)]
    struct Ordered {
        z: u64,
        a: serde_json::Value,
    }
    let object = Ordered {
        z: 42,
        a: serde_json::json!({"z":2,"a":1}),
    };
    let same = serde_json::json!({"a":{"a":1,"z":2}, "z":42});
    let signature = sign_domain(&[7; 32], "lattice/certificate/v1", &object).unwrap();
    verify_domain(
        &encode_key(&public_key(&[7; 32])),
        "lattice/certificate/v1",
        &signature,
        &same,
    )
    .unwrap();
    assert_eq!(
        signature,
        sign_domain(&[7; 32], "lattice/certificate/v1", &same).unwrap()
    );
}

#[test]
fn canonical_v1_rejects_float_and_ambiguous_domain_labels() {
    assert!(
        sign_domain(
            &[7; 32],
            "lattice/certificate/v1",
            &serde_json::json!({"expiry":1.5})
        )
        .is_err()
    );
    assert!(sign_domain(&[7; 32], "", &true).is_err());
    assert!(sign_domain(&[7; 32], "certificate\0command", &true).is_err());
}
