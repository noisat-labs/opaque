use rand::{ Rng, CryptoRng };
use serde::{ Serialize, de::DeserializeOwned };
use crate::Envelope;


pub trait AuthKeyExchange {
    type PrivateKey: Serialize + DeserializeOwned;
    type PublicKey: Serialize + DeserializeOwned + Clone;
    type EphemeralKey: Serialize + DeserializeOwned;
    type Message: Serialize + DeserializeOwned + Clone;

    const SHARED_LENGTH: usize;

    fn keypair<R: Rng + CryptoRng>(r: R) -> (Self::PrivateKey, Self::PublicKey);
    fn generate_ephemeral<R: Rng + CryptoRng>(r: R) -> Self::EphemeralKey;
    fn to_message(ek: &Self::EphemeralKey) -> Self::Message;
    fn enc(
        sharedkey: &mut [u8],
        aid: &str, ask: &Self::PrivateKey,
        bid: &str, bpk: &Self::PublicKey,
        ek: &Self::EphemeralKey,
        m: &Self::Message
    ) -> Result<(), ()>;
    fn dec(
        sharedkey: &mut [u8],
        bid: &str, bsk: &Self::PrivateKey,
        aid: &str, apk: &Self::PublicKey,
        ek: &Self::EphemeralKey,
        m: &Self::Message
    ) -> Result<(), ()>;
}

pub trait AuthEnc<AKE: AuthKeyExchange> {
    const KEY_LENGTH: usize;

    fn seal<R: Rng + CryptoRng>(r: R, key: &[u8], input: &Envelope<AKE>) -> Vec<u8>;
    fn open(key: &[u8], input: &[u8]) -> Result<Envelope<AKE>, ()>;
}

pub trait PwHash {
    fn pwhash(salt: &[u8], input: &[u8], output: &mut [u8]);
}
