use rand::{ Rng, CryptoRng };
use digest::Digest;
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::U64;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;


pub struct PrivateKey(pub Scalar);
pub struct PublicKey(pub RistrettoPoint);
pub struct Challenge(RistrettoPoint);
pub struct Response(RistrettoPoint);

pub struct Process<H> {
    hash: H,
    r: Scalar
}

pub fn oprf<H>(PrivateKey(k): &PrivateKey, x: &[u8])
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

pub fn challenge<R, H>(rng: &mut R, x: &[u8])
    -> (Process<H>, Challenge)
where
    R: Rng + CryptoRng,
    H: Digest<OutputSize = U64> + Default
{
    let r = Scalar::random(rng);
    let point = RistrettoPoint::hash_from_bytes::<H>(x);
    let c = point + &RISTRETTO_BASEPOINT_TABLE * &r;
    let p = Process { hash: H::default().chain(x), r };

    (p, Challenge(c))
}

pub fn response(PrivateKey(k): &PrivateKey, Challenge(a): Challenge) -> Response {
    Response(a * k)
}

pub fn oprf2<H>(
    PublicKey(v): &PublicKey,
    Process { hash, r }: Process<H>,
    Response(b): Response
)
    -> GenericArray<u8, H::OutputSize>
where H: Digest<OutputSize = U64> + Default + Clone
{
    let s = b + v * (-r);

    hash
        .chain(v.compress().as_bytes())
        .chain(s.compress().as_bytes())
        .result()
}
