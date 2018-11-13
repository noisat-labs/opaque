use arrayref::{ array_ref, array_mut_ref };
use rand::{ Rng, CryptoRng };
use opaque::traits::{ AuthKeyExchange, AuthEnc, PwHash };
use opaque::Envelope;
pub use sha3::Sha3_512;


pub struct Oake;

impl AuthKeyExchange for Oake {
    type PrivateKey = oake::SecretKey;
    type PublicKey = oake::PublicKey;
    type EphemeralKey = oake::EphemeralKey;
    type Message = oake::Message;

    const SHARED_LENGTH: usize = 32;

    fn keypair<R: Rng + CryptoRng>(mut r: R) -> (Self::PrivateKey, Self::PublicKey) {
        let sk = oake::SecretKey::generate(&mut r);
        let pk = oake::PublicKey::from_secret(&sk);
        (sk, pk)
    }

    fn generate_ephemeral<R: Rng + CryptoRng>(mut r: R) -> Self::EphemeralKey {
        oake::EphemeralKey::generate(&mut r)
    }

    fn to_message(ek: &Self::EphemeralKey) -> Self::Message {
        oake::Message::from_ephemeral(ek)
    }

    fn enc(
        sharedkey: &mut [u8],
        aid: &str, ask: &Self::PrivateKey,
        bid: &str, bpk: &Self::PublicKey,
        ek: &Self::EphemeralKey,
        m: &Self::Message
    ) -> Result<(), ()> {
        let apk = oake::PublicKey::from_secret(ask);
        let epk = oake::Message::from_ephemeral(ek);

        oake::oake::send(
            (aid, ask, &apk),
            (bid, bpk),
            (ek, &epk),
            m,
            sharedkey
        ).map_err(drop)
    }

    fn dec(
        sharedkey: &mut [u8],
        bid: &str, bsk: &Self::PrivateKey,
        aid: &str, apk: &Self::PublicKey,
        ek: &Self::EphemeralKey,
        m: &Self::Message
    ) -> Result<(), ()> {
        let bpk = oake::PublicKey::from_secret(bsk);
        let epk = oake::Message::from_ephemeral(ek);

        oake::oake::recv(
            (bid, bsk, &bpk),
            (aid, apk),
            (ek, &epk),
            m,
            sharedkey
        ).map_err(drop)
    }
}

pub struct NorxCbor;

impl<AKE: AuthKeyExchange> AuthEnc<AKE> for NorxCbor {
    const KEY_LENGTH: usize = norx::constant::KEY_LENGTH + norx::constant::NONCE_LENGTH;

    fn seal(key: &[u8], input: &Envelope<AKE>) -> Vec<u8> {
        use norx::constant::{ KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, BLOCK_LENGTH };

        let (key, nonce) = key.split_at(KEY_LENGTH);
        let key = array_ref!(key, 0, KEY_LENGTH);
        let nonce = array_ref!(nonce, 0, NONCE_LENGTH);

        let m = serde_cbor::to_vec(input).unwrap();
        let mut c = vec![0; m.len() + TAG_LENGTH];

        let (m1, m2) = m.split_at(m.len() - m.len() % BLOCK_LENGTH);
        let (c1, c2) = c.split_at_mut(m1.len());

        let mut process = norx::Norx::new(key, nonce).encrypt(b"");
        process.process(
            m1.chunks(BLOCK_LENGTH)
                .zip(c1.chunks_mut(BLOCK_LENGTH))
                .map(|(x, y)| (
                    array_ref!(x, 0, BLOCK_LENGTH),
                    array_mut_ref!(y, 0, BLOCK_LENGTH)
                ))
        );
        process.finalize(key, &[], m2, c2);

        c
    }

    fn open(key: &[u8], input: &[u8]) -> Result<Envelope<AKE>, ()> {
        use norx::constant::{ KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, BLOCK_LENGTH };

        let (key, nonce) = key.split_at(KEY_LENGTH);
        let key = array_ref!(key, 0, KEY_LENGTH);
        let nonce = array_ref!(nonce, 0, NONCE_LENGTH);

        let c = input;
        let m_len = input.len() - TAG_LENGTH;
        let mut m = vec![0; m_len];
        let (m1, m2) = m.split_at_mut(m_len - m_len % BLOCK_LENGTH);
        let (c1, c2) = c.split_at(m1.len());

        let mut process = norx::Norx::new(key, nonce).decrypt(b"");
        process.process(
            c1.chunks(BLOCK_LENGTH)
                .zip(m1.chunks_mut(BLOCK_LENGTH))
                .map(|(x, y)| (
                    array_ref!(x, 0, BLOCK_LENGTH),
                    array_mut_ref!(y, 0, BLOCK_LENGTH)
                ))
        );

        if process.finalize(key, &[], c2, m2) {
            serde_cbor::from_slice(&m)
                .map_err(drop)
        } else {
            Err(())
        }
    }
}

pub struct Scrypt;

impl PwHash for Scrypt {
    fn pwhash(salt: &[u8], input: &[u8], output: &mut [u8]) {
        let params = scrypt::ScryptParams::new(14, 8 ,1).unwrap();
        scrypt::scrypt(input, salt, &params, output).unwrap();
    }
}
