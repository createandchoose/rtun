use boringtun::x25519::{PublicKey, StaticSecret};

pub fn keypair() -> (String, String) {
    let private = rt_proto::keys::generate_private_key();
    let public = rt_proto::keys::public_key_from_private(&private).expect("generated key is valid");
    (private, public)
}

pub fn tunnel_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut private);
    let secret = StaticSecret::from(private);
    let public = *PublicKey::from(&secret).as_bytes();
    (private, public)
}
