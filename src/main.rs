use bec_broadcast::Broadcaster;

fn main() {
    let mut peer1 = Broadcaster::init();
    let mut peer2 = Broadcaster::init();

    let msg = peer1.initialize_connection(peer2.id()).unwrap();
    let msg = peer2.establish_connection(msg).unwrap();
    peer1.receive_ack(msg).unwrap();

    println!("{:?}", peer1);
    println!("{:?}", peer2);
}
