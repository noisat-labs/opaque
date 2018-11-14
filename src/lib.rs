pub mod oprf;
pub mod traits;

use std::marker::PhantomData;
use rand::{ Rng, CryptoRng };
use digest::Digest;
use digest::generic_array::typenum::U64;
use serde_derive::{ Serialize, Deserialize };
use crate::traits::{ AuthEnc, AuthKeyExchange, PwHash };


pub struct Server<AKE: AuthKeyExchange> {
    pub name: String,
    pub sk: AKE::PrivateKey,
    pub pk: AKE::PublicKey
}

#[derive(Serialize, Deserialize)]
pub struct UserData<T>(pub oprf::PrivateKey, pub T);

pub struct User<AKE, AE, PH, T>(PhantomData<(AKE, AE, PH)>, T);
pub struct Register<H>(oprf::Process<H>);
pub struct Login<AKE: AuthKeyExchange, H>(oprf::Process<H>, AKE::EphemeralKey);

#[derive(Serialize, Deserialize)]
pub struct Envelope<AKE: AuthKeyExchange> {
    pub privu: AKE::PrivateKey,
    pub pubu: AKE::PublicKey,
    pub pubs: AKE::PublicKey,
    pub vu: oprf::PublicKey
}

#[derive(Serialize, Deserialize)]
pub struct UserRegisterMessage {
    pub challenge: oprf::Challenge
}

#[derive(Serialize, Deserialize)]
pub struct UserEnvelope<AKE: AuthKeyExchange> {
    pub envelope: Vec<u8>,
    pub pubu: AKE::PublicKey
}

#[derive(Serialize, Deserialize)]
pub struct ServerRegisterMessage {
    pub vu: oprf::PublicKey,
    pub resp: oprf::Response
}

#[derive(Serialize, Deserialize)]
pub struct UserLoginMessage<AKE: AuthKeyExchange> {
    pub msg: AKE::Message,
    pub challenge: oprf::Challenge
}

#[derive(Serialize, Deserialize)]
pub struct ServerLoginMessage<AKE: AuthKeyExchange> {
    pub vu: oprf::PublicKey,
    pub msg: AKE::Message,
    pub resp: oprf::Response,
    pub envelope: Vec<u8>
}

impl UserData<()> {
    pub fn add<AKE: AuthKeyExchange>(self, envelope: UserEnvelope<AKE>)
        -> UserData<UserEnvelope<AKE>>
    {
        let UserData(ku, ()) = self;
        UserData(ku, envelope)
    }
}

impl<AKE: AuthKeyExchange> Server<AKE> {
    pub fn new<NAME: Into<String>, R: Rng + CryptoRng>(rng: R, name: NAME) -> Self {
        let (sk, pk) = AKE::keypair(rng);
        Server { sk, pk, name: name.into() }
    }

    pub fn register<R: Rng + CryptoRng>(rng: R, UserRegisterMessage { challenge }: UserRegisterMessage)
        -> (UserData<()>, ServerRegisterMessage)
    {
        let (ku, vu) = oprf::keypair(rng);
        let resp = oprf::response(&ku, challenge);
        (UserData(ku, ()), ServerRegisterMessage { vu, resp })
    }

    pub fn login<R: Rng + CryptoRng>(
        &self,
        rng: R,
        username: &str,
        UserData(ku, UserEnvelope { envelope, pubu }): &UserData<UserEnvelope<AKE>>,
        UserLoginMessage { msg, challenge }: UserLoginMessage<AKE>,
        sharedkey: &mut [u8]
    )
        -> Result<ServerLoginMessage<AKE>, ()>
    {
        let ek = AKE::generate_ephemeral(rng);
        let resp = oprf::response(ku, challenge);

        AKE::dec(
            sharedkey,
            &self.name, &self.sk,
            username, pubu,
            &ek,
            &msg
        ).map(|_| ServerLoginMessage {
            vu: ku.to_public(),
            msg: AKE::to_message(&ek),
            envelope: envelope.clone(),
            resp
        })
    }
}

impl<AKE, AE, PH, H> User<AKE, AE, PH, Register<H>>
where
    AKE: AuthKeyExchange,
    AE: AuthEnc<AKE>,
    PH: PwHash,
    H: Digest<OutputSize = U64> + Default,
{
    pub fn start<R: Rng + CryptoRng>(rng: R, pw: &[u8]) -> (Self, UserRegisterMessage) {
        let (process, challenge) = oprf::challenge::<H, _>(rng, pw);
        (User(PhantomData, Register(process)), UserRegisterMessage { challenge })
    }

    pub fn next<R: Rng + CryptoRng>(
        self,
        rng: R,
        username: &str,
        pubs: AKE::PublicKey,
        ServerRegisterMessage { vu, resp }: ServerRegisterMessage
    ) -> UserEnvelope<AKE> {
        let User(_, Register(process)) = self;
        let (privu, pubu) = AKE::keypair(rng);

        let rwd = oprf::f(&vu, process, resp);
        let mut rwdk = vec![0; AE::KEY_LENGTH];
        PH::pwhash(username.as_bytes(), &rwd, &mut rwdk);

        let envu = Envelope { privu, pubu, pubs, vu };

        UserEnvelope {
            envelope: AE::seal(&rwdk, &envu),
            pubu: envu.pubu
        }
    }
}

impl<AKE, AE, PH, H> User<AKE, AE, PH, Login<AKE, H>>
where
    AKE: AuthKeyExchange,
    AE: AuthEnc<AKE>,
    PH: PwHash,
    H: Digest<OutputSize = U64> + Default,
{
    pub fn start<R: Rng + CryptoRng>(mut rng: R, pw: &[u8])
        -> (User<AKE, AE, PH, Login<AKE, H>>, UserLoginMessage<AKE>)
    {
        let (process, challenge) = oprf::challenge::<H, _>(&mut rng, pw);

        let ek = AKE::generate_ephemeral(&mut rng);
        let msg = AKE::to_message(&ek);

        (User(PhantomData, Login(process, ek)), UserLoginMessage { msg, challenge })
    }

    pub fn next(
        self,
        username: &str,
        servername: &str,
        ServerLoginMessage { vu, msg, resp, envelope }: ServerLoginMessage<AKE>,
        sharedkey: &mut [u8]
    ) -> Result<(), ()> {
        let User(_, Login(process, ek)) = self;

        let rwd = oprf::f(&vu, process, resp);
        let mut rwdk = vec![0; AE::KEY_LENGTH];
        PH::pwhash(username.as_bytes(), &rwd, &mut rwdk);
        let envu = AE::open(&rwdk, &envelope)?;

        AKE::enc(
            sharedkey,
            username, &envu.privu,
            servername, &envu.pubs,
            &ek,
            &msg
        )
    }
}
