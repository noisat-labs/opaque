mod common;

use opaque::{ Server, User, Register, Login };
use crate::common::oake_norx_scrypt_sha3_cbor::*;



#[test]
fn test_opaque() {
    let mut rng = rand::thread_rng();
    let passwd = b"password";

    let server = Server::<Oake>::new(&mut rng, "server");

    let (user, msg) = User::<Register<Sha3_512>>::start(&mut rng, passwd);
    let (userdata, msg) = Server::<Oake>::register(&mut rng, msg);
    let envu = user.next::<Oake, NorxCbor, Scrypt, _>(&mut rng, "user", server.pk.clone(), msg);
    let userdata = userdata.add(envu);

    let (mut rwds, mut rwdu) = ([0; 32], [0; 32]);
    let (user, msg) = User::<Login<Oake, Sha3_512>>::start(&mut rng, passwd);
    let msg = server.login(&mut rng, "user", userdata, msg, &mut rwds).unwrap();
    user.next::<NorxCbor, Scrypt>("user", "server", msg, &mut rwdu).unwrap();

    assert_eq!(rwds, rwdu);
}
