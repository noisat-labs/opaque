use rand::{ Rng, CryptoRng };
use digest::Digest;
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::U64;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use serde_derive::{ Serialize, Deserialize };


#[derive(Serialize, Deserialize)]
pub struct PrivateKey(Scalar);

#[derive(Serialize, Deserialize)]
pub struct PublicKey(RistrettoPoint);

pub struct Process<H>(H, Scalar);

#[derive(Serialize, Deserialize)]
pub struct Challenge(RistrettoPoint);

#[derive(Serialize, Deserialize)]
pub struct Response(RistrettoPoint);

impl PrivateKey {
    pub fn random<R: Rng + CryptoRng>(mut rng: R) -> PrivateKey {
        PrivateKey(Scalar::random(&mut rng))
    }

    pub fn to_public(&self) -> PublicKey {
        PublicKey(&RISTRETTO_BASEPOINT_TABLE * &self.0)
    }
}

pub fn keypair<R: Rng + CryptoRng>(rng: R) -> (PrivateKey, PublicKey) {
    let sk = PrivateKey::random(rng);
    let pk = sk.to_public();
    (sk, pk)
}

pub fn priv_f<H>(PrivateKey(k): &PrivateKey, x: &[u8])
    -> GenericArray<u8, H::OutputSize>
where H: Digest<OutputSize = U64> + Default
{
    let point = RistrettoPoint::hash_from_bytes::<H>(x);
    let pk = &RISTRETTO_BASEPOINT_TABLE * k;
    let s = point * k;

    H::default()
        .chain(x)
        .chain(pk.compress().as_bytes())
        .chain(s.compress().as_bytes())
        .result()
}

pub fn challenge<H, R>(mut rng: R, x: &[u8])
    -> (Process<H>, Challenge)
where
    H: Digest<OutputSize = U64> + Default,
    R: Rng + CryptoRng
{
    let r = Scalar::random(&mut rng);
    let point = RistrettoPoint::hash_from_bytes::<H>(x);
    let c = point + &RISTRETTO_BASEPOINT_TABLE * &r;
    let p = Process(H::default().chain(x), r);

    (p, Challenge(c))
}

pub fn response(PrivateKey(k): &PrivateKey, Challenge(a): Challenge) -> Response {
    Response(a * k)
}

pub fn f<H>(
    PublicKey(v): &PublicKey,
    Process(hash, r): Process<H>,
    Response(b): Response
)
    -> GenericArray<u8, H::OutputSize>
where H: Digest<OutputSize = U64> + Default
{
    let s = b + v * (-r);

    hash
        .chain(v.compress().as_bytes())
        .chain(s.compress().as_bytes())
        .result()
}
