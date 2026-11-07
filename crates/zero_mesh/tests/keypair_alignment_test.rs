//! Keypair alignment and negative AEAD control tests (unification-016).

use std::cell::RefCell;
use std::rc::Rc;

use zero_mesh::crypto::ChatSessionCrypto;
use zero_mesh::mesh::MeshTopology;
use zero_mesh::webrtc::WebRtcPeer;
use zero_protocol::crypto::x25519::X25519Keypair;

fn generate_kp() -> ([u8; 32], [u8; 32]) {
    let kp = X25519Keypair::generate().expect("keypair");
    (*kp.private_key_bytes(), *kp.public_key_bytes())
}

/// Negative control: sealing with one shared secret and opening with a
/// mismatched (third-party) public key must fail AEAD authentication.
#[test]
fn test_mismatched_keypair_fails_aead() {
    let (alice_sk, alice_pk) = generate_kp();
    let (bob_sk, bob_pk) = generate_kp();
    let (_mallory_sk, mallory_pk) = generate_kp();

    // Alice seals using the correct Alice<->Bob shared secret.
    let alice_crypto = ChatSessionCrypto::from_keypair_and_peer_public(&alice_sk, &bob_pk);
    let sealed = alice_crypto
        .seal_raw(b"top secret payload")
        .expect("seal succeeds");

    // Bob opens using the correct shared secret: succeeds.
    let bob_crypto = ChatSessionCrypto::from_keypair_and_peer_public(&bob_sk, &alice_pk);
    let opened = bob_crypto.open_raw(&sealed).expect("correct key opens");
    assert_eq!(opened, b"top secret payload");

    // Bob (mis-registered) opens using a mismatched public key: must fail AEAD.
    let mismatched_crypto =
        ChatSessionCrypto::from_keypair_and_peer_public(&bob_sk, &mallory_pk);
    let err = mismatched_crypto.open_raw(&sealed);
    assert!(
        err.is_err(),
        "AEAD open must fail when the peer public key is mismatched"
    );
}

/// `set_local_peer_id` must preserve registered peers and migrate
/// local-ID-keyed vector-clock state to the new identity.
#[test]
fn test_set_local_peer_id_preserves_state() {
    let (alice_sk, _alice_pk) = generate_kp();
    let mesh = MeshTopology::new("walker-bootstrap", alice_sk);

    // Register a peer.
    let (_bob_sk, bob_pk) = generate_kp();
    let bob_peer = WebRtcPeer::new();
    bob_peer.mark_open_for_testing().unwrap();
    mesh.add_peer("bob", bob_pk, bob_peer).expect("add bob");

    // Record a vector-clock style sequence number under the old local ID.
    mesh.set_sequence_number("walker-bootstrap", 42);
    assert_eq!(mesh.sequence_number("walker-bootstrap"), Some(42));

    // Reassign local identity.
    mesh.set_local_peer_id("peer-xyz");

    // Peer registration preserved.
    assert_eq!(mesh.local_peer_id(), "peer-xyz");
    assert!(mesh.has_peer("bob"));
    assert_eq!(mesh.peer_count(), 1);

    // Vector-clock state migrated to the new ID.
    assert_eq!(mesh.sequence_number("peer-xyz"), Some(42));
    assert_eq!(mesh.sequence_number("walker-bootstrap"), None);
}

/// Callbacks registered before `set_local_peer_id` remain functional afterwards.
#[test]
fn test_set_local_peer_id_preserves_callbacks() {
    let (alice_sk, _alice_pk) = generate_kp();
    let mesh = MeshTopology::new("walker-bootstrap", alice_sk);

    let joined = Rc::new(RefCell::new(Vec::new()));
    let j = joined.clone();
    mesh.on_peer_joined(move |id| j.borrow_mut().push(id.to_string()));

    mesh.set_local_peer_id("peer-xyz");

    let (_bob_sk, bob_pk) = generate_kp();
    let bob_peer = WebRtcPeer::new();
    bob_peer.mark_open_for_testing().unwrap();
    mesh.add_peer("bob", bob_pk, bob_peer).expect("add bob");

    assert_eq!(*joined.borrow(), vec!["bob".to_string()]);
}
