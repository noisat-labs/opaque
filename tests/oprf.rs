use rand::Rng;
use sha3::Sha3_512;
use opaque::oprf;


#[test]
fn test_oprf() {
    let mut rng = rand::thread_rng();
    let mut pw = [0; 16];
    rng.fill(&mut pw);

    let (sk, pk) = oprf::keypair(&mut rng);
    let rw = oprf::priv_f::<Sha3_512>(&sk, &pw);

    let (p, c) = oprf::challenge::<Sha3_512, _>(&mut rng, &pw);
    let resp = oprf::response(&sk, c);
    let rw2 = oprf::f(&pk, p, resp);

    assert_eq!(rw, rw2);
}
