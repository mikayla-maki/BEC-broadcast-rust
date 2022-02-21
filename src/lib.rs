use std::fmt;
use std::collections::HashMap;
use std::collections::HashSet;
use tweet_nacl_rust::x25519::{generate_keypair, random_bytes, scalarmult_base, x25519};
// use sha2::{Sha256, Digest};

//Variable names are set to match those in the reference paper: https://arxiv.org/pdf/2012.00472.pdf
type PublicKey = [u8; 32];
type PrivateKey = [u8; 32];
type SharedSecret = [u8; 32];
type Signature = [u8; 32];

const ACK_DATA: u32 = u32::MAX;

//To is the receiver of the connection request, e.g. 'Bob'
pub struct EstablishConnection {
    from: PublicKey,
    to: PublicKey,
    gk: [u8; 32],
}

//To the initiator of the connection request, e.g. 'Alice'
pub struct AcknowledgeConnection {
    from: PublicKey,
    to: PublicKey,
    //Prove that we've established the shared secret
    signed: i64, //TODO Don't know the signed data type yet
}

pub struct DropConnection {
    from: PublicKey,
    to: PublicKey,
    signed: i64, //TODO don't know what to do here
}

//??
pub struct BroadcastMessage {
    v: String,        //The message to be sent
    hs: HashSet<i64>, //A set of hashes
    sig: Signature,   //Digital signature of the (v, hs) items (sha-256)
}

//???
pub struct NeedsHashes {
    hs: HashSet<i64>,
}

// pub enum Message {
//     Establish(EstablishConnection),
//     Acknowledge(AcknowledgeConnection),
//     Drop(DropConnection),

//     Broadcast(BroadcastMessage),
//     Needs(NeedsHashes),
// }

pub struct Broadcaster {
    private_key: PrivateKey,
    id: PublicKey,
    // m: Vec<Message>, //TODO, change to merkle tree????? idk yet....
    //Peer ID, the shared secret, and whether this peer has been acknowledged
    peers: HashMap<PublicKey, (SharedSecret, bool)>, //Probably better to have a HashSet
}

impl fmt::Debug for Broadcaster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut peers_out = "".to_string();
        for (key, (secret, connected)) in &self.peers {
            if peers_out != "" {
                peers_out = format!("{}, ", peers_out);
            }
            let formatted_entry = format!("({} => {}, {})", readable_id(key), readable_key(secret), connected);
            peers_out = format!("{}{}", peers_out, formatted_entry);
        }

        f.debug_struct("Broadcaster")
         .field("id", &readable_id(&self.id))
         .field("private_key", &readable_key(&self.private_key))
         .field("peers", &format_args!("{:?}", peers_out))
         .finish()
    }
}


impl Broadcaster {
    pub fn init() -> Broadcaster {
        let (pk, sk) = generate_keypair();

        Broadcaster {
            private_key: sk,
            id: pk,
            // m: vec![],
            peers: HashMap::new(),
        }
    }

    pub fn id(&self) -> PublicKey {
        self.id
    }

    //Alice calls this internally with Bob's PublicKey, generates the shared secret
    pub fn initialize_connection(&mut self, id: PublicKey) -> Result<EstablishConnection, String> {
        if let Some((_, true)) = self.peers.get(&id) {
            return Err(format!("Already connected to {}", readable_id(&id)));
        }

        let k = random_bytes();
        let shared_secret = x25519(id, k);
        self.peers.insert(id, (shared_secret, false));

        Ok(EstablishConnection {
            from: self.id,
            to: id,
            gk: scalarmult_base(k),
        })
    }

    //Bob receives Alice's message, generates the shared secret and sends and acknowledgment
    pub fn establish_connection(&mut self, ec: EstablishConnection) -> Result<AcknowledgeConnection, String> {
        if let Some((_, true)) = self.peers.get(&ec.from) {
            return Err(format!("Already connected to {}", readable_id(&ec.from)));
        }

        let shared_secret = x25519(ec.gk, self.private_key);
        self.peers.insert(ec.from, (shared_secret, true));

        Ok(AcknowledgeConnection {
            from: self.id,
            to: ec.from,
            signed: ACK_DATA as i64,
        })
    }

    pub fn receive_ack(&mut self, ac: AcknowledgeConnection) -> Result<(), String> {
        match self.peers.get(&ac.from) {
            Some((shared_secret, false)) => {
                if ac.signed == ACK_DATA as i64 {
                    self.peers.insert(ac.from, (*shared_secret, true));
                    Ok(())
                } else {
                    Err(format!("False signature from {}", readable_id(&ac.from)))
                }
            }
            Some((shared_secret, true)) => Err(format!("Already ack-ed {}", readable_id(&ac.from))),
            None => Err(format!(
                "Have not initiated connection with {}",
                readable_id(&ac.from)
            )),
        }
    }

    pub fn drop(&mut self, id: PublicKey) -> Result<DropConnection, String> {
        if !self.peers.contains_key(&id) {
            return Err(format!("No connection to drop with {}", readable_id(&id)));
        }

        self.peers.remove(&id);

        //Notify the other end of the drop
        Ok(DropConnection {
            from: self.id,
            to: id,
            signed: ACK_DATA as i64,
        })
    }

    pub fn drop_connection(&mut self, dc: DropConnection) -> Result<(), String> {
        match self.peers.get(&dc.from) {
            Some((shared_secret, _)) => {
                if dc.signed == ACK_DATA as i64 {
                    self.peers.remove(&dc.from);
                    Ok(())
                } else {
                    return Err(format!("False signature from {}", readable_id(&dc.from)));
                }
            }
            _ => Err(format!(
                "No connection to drop with {}",
                readable_id(&dc.from)
            )),
        }
    }

    pub fn broadcast(&mut self, v: &str) {
    //     self.hasher.update(v);//TODO throw the merkletree into there too
    //     let hash = self.hasher.finalize_reset();

    //     let mut array_hash:[u8; 32] = [0; 32]; //I'm sure there's a nicer way to do this...
    //     for i in 0..32 {
    //         array_hash[i] = hash[i];
    //     }

    //     let msg = Message {
    //         v: v.to_string(),
    //         sig: array_hash,
    //         hs: HashSet::new() //TODO build merkle tree
    //     };

    //     self.receive(&msg);
    //     for (peer, _) in &self.peers {
    //         peer.receive(&msg);
    //     }
    }

    // fn receive(&self, msg: &Message) {
    //     println!("- {} Received: {}", self.id, msg.v);
    // }
}

fn readable_key(data: &[u8; 32]) -> String {
    let out = format!("{:02x}{:02x}{:02x}", data[31], data[30], data[29]);
    out.replace("0x", "")
}


fn readable_id(id: &PublicKey) -> String {
    let nibble: u8 = id[31] & 0xf; //Little endian order
    let id_let = match nibble {
        0 => "A",
        1 => "B",
        2 => "C",
        3 => "D",
        4 => "E",
        5 => "F",
        6 => "G",
        7 => "H",
        8 => "I",
        9 => "J",
        10 => "K",
        11 => "L",
        12 => "M",
        13 => "N",
        14 => "O",
        15 => "P",
        16 => "Q",
        _ => "XXX"
    };

    format!("{} - {}", id_let, readable_key(id))
}
