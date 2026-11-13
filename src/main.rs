//! net-bench: FROST vs CGGMP threshold signing over a real network.
//!
//! Every party is a separate process, normally on a separate machine, and the
//! parties exchange messages over TCP. Node 0 is the coordinator: it sends the
//! signing request, collects the result and measures the end-to-end latency.
//! Node 0 is also one of the signers. With threshold t, nodes 0..t-1 sign.
//!
//! Usage (one command per node, same config file on every machine):
//!   net-bench --id 0 --config nodes.txt --proto frost --t 2 --count 200
//!   net-bench --id 1 --config nodes.txt --proto frost --t 2
//!   net-bench --id 2 --config nodes.txt --proto frost --t 2
//!
//! nodes.txt contains one line per node: "<id> <host>:<port>".
//! Node i connects to every node j > i, so only nodes with higher ids must
//! accept incoming connections (put a machine behind NAT at the low ids).
//!
//! Key material is produced by a dealer with a fixed seed, so that every
//! machine derives the same keys without copying files; a fingerprint of the
//! joint public key is checked when the nodes connect. This is for
//! benchmarking only: a real deployment uses distributed key generation.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use manul::dev::{BinaryFormat, TestSessionParams, TestSigner, TestVerifier};
use manul::protocol::RoundId;
use manul::session::{
    CanFinalize, Message, RoundAccumulator, RoundOutcome, Session, SessionId, SessionOutcome,
};
use manul::signature::Keypair;
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use synedrion::k256::ProductionParams112;
use synedrion::{AuxInfo, InteractiveSigning, InteractiveSigningProtocol, ThresholdKeyShare};

use frost_secp256k1_tr as frost;

type Params = ProductionParams112;
type SP = TestSessionParams<BinaryFormat>;
type CggmpProto = InteractiveSigningProtocol<Params, TestVerifier>;

const SEED: u64 = 0x5EED_2027;

// ===========================================================================
// Command line
// ===========================================================================

#[derive(Clone, Debug)]
struct Args {
    id: u8,
    config: String,
    proto: String,
    t: usize,
    count: usize,
    warmup: usize,
    pings: usize,
    label: String,
    out: String,
    delay_ms: f64,
}

fn parse_args() -> Args {
    let mut a = Args {
        id: 0,
        config: "nodes.txt".into(),
        proto: "frost".into(),
        t: 2,
        count: 0,
        warmup: 0,
        pings: 50,
        label: "net".into(),
        out: "results".into(),
        delay_ms: 0.0,
    };
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let val = || v.get(i + 1).cloned().unwrap_or_default();
        match v[i].as_str() {
            "--id" => a.id = val().parse().expect("--id"),
            "--config" => a.config = val(),
            "--proto" => a.proto = val(),
            "--t" => a.t = val().parse().expect("--t"),
            "--count" => a.count = val().parse().expect("--count"),
            "--warmup" => a.warmup = val().parse().expect("--warmup"),
            "--pings" => a.pings = val().parse().expect("--pings"),
            "--label" => a.label = val(),
            "--out" => a.out = val(),
            "--delay-ms" => a.delay_ms = val().parse().expect("--delay-ms"),
            "-h" | "--help" => {
                println!("see the header of src/main.rs or README.md");
                std::process::exit(0);
            }
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    if a.count == 0 {
        a.count = if a.proto.starts_with("frost") { 200 } else { 20 };
    }
    if a.warmup == 0 {
        a.warmup = if a.proto.starts_with("frost") { 20 } else { 2 };
    }
    a
}

fn read_config(path: &str) -> BTreeMap<u8, String> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let mut m = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let id: u8 = it.next().unwrap().parse().expect("node id");
        let addr = it.next().expect("host:port").to_string();
        m.insert(id, addr);
    }
    let ids: Vec<u8> = m.keys().cloned().collect();
    assert_eq!(ids, (0..ids.len() as u8).collect::<Vec<_>>(), "node ids must be 0..n-1");
    m
}

// ===========================================================================
// Wire messages and transport
// ===========================================================================

#[derive(Serialize, Deserialize, Debug)]
enum Net {
    Hello { id: u8, fp: [u8; 8] },
    Ping { k: u32 },
    Pong { k: u32 },
    Start { seq: u32, digest: [u8; 32] },
    /// FROST with preprocessing: signers publish commitments for seqs start..start+count in advance
    Precompute { start: u32, count: u32 },
    FrostCommit { seq: u32, data: Vec<u8> },
    FrostPkg { seq: u32, data: Vec<u8> },
    FrostShare { seq: u32, data: Vec<u8> },
    Mpc { seq: u32, data: Vec<u8> },
    Done { seq: u32, offline_us: u64, online_us: u64, cpu_us: u64, ok: bool },
    Quit,
}

fn write_frame(s: &mut TcpStream, m: &Net) -> usize {
    let bytes = postcard::to_allocvec(m).expect("serialize");
    let len = (bytes.len() as u32).to_le_bytes();
    s.write_all(&len).and_then(|_| s.write_all(&bytes)).expect("send");
    bytes.len() + 4
}

fn read_frame(s: &mut TcpStream) -> Option<Net> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).ok()?;
    let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
    s.read_exact(&mut buf).ok()?;
    postcard::from_bytes(&buf).ok()
}

struct Network {
    me: u8,
    #[allow(dead_code)]
    peers: BTreeMap<u8, Arc<Mutex<TcpStream>>>,
    out: BTreeMap<u8, Sender<(Instant, Vec<u8>)>>,
    delay: Duration,
    rx: Receiver<(u8, Net)>,
    self_tx: Sender<(u8, Net)>,
    bytes_sent: usize,
}

impl Network {
    fn connect(me: u8, cfg: &BTreeMap<u8, String>, fp: [u8; 8], delay_ms: f64) -> Network {
        let (tx, rx) = channel();
        let port = cfg[&me].rsplit(':').next().unwrap().to_string();
        let listener = TcpListener::bind(format!("0.0.0.0:{port}")).expect("bind (port in use?)");
        let mut peers: BTreeMap<u8, Arc<Mutex<TcpStream>>> = BTreeMap::new();

        let check = |id: u8, their: [u8; 8]| {
            if their != fp {
                panic!("node {id} uses different key material (fingerprint mismatch): same --proto and --t on all nodes?");
            }
        };

        // connect to higher ids
        for (&j, addr) in cfg.range(me + 1..) {
            let mut tries = 0;
            let s = loop {
                match TcpStream::connect(addr) {
                    Ok(s) => break s,
                    Err(_) => {
                        tries += 1;
                        if tries % 10 == 1 {
                            println!("  waiting for node {j} at {addr} ...");
                        }
                        thread::sleep(Duration::from_millis(500));
                    }
                }
            };
            s.set_nodelay(true).ok();
            let mut s2 = s.try_clone().unwrap();
            write_frame(&mut s2, &Net::Hello { id: me, fp });
            match read_frame(&mut s2) {
                Some(Net::Hello { id, fp: f }) => {
                    assert_eq!(id, j);
                    check(j, f);
                }
                _ => panic!("handshake with node {j} failed"),
            }
            peers.insert(j, Arc::new(Mutex::new(s)));
            println!("  connected to node {j} ({addr})");
        }
        // accept lower ids
        let lower = cfg.range(..me).count();
        let mut accepted = 0;
        if lower > 0 {
            println!("  listening on port {port} for {lower} node(s)");
        }
        while accepted < lower {
            let (mut s, addr) = listener.accept().expect("accept");
            s.set_nodelay(true).ok();
            match read_frame(&mut s) {
                Some(Net::Hello { id, fp: f }) => {
                    check(id, f);
                    write_frame(&mut s, &Net::Hello { id: me, fp });
                    println!("  node {id} connected from {addr}");
                    peers.insert(id, Arc::new(Mutex::new(s)));
                    accepted += 1;
                }
                _ => println!("  ignored a connection from {addr}"),
            }
        }
        // reader threads
        for (&j, s) in &peers {
            let mut r = s.lock().unwrap().try_clone().unwrap();
            let tx = tx.clone();
            thread::spawn(move || {
                while let Some(m) = read_frame(&mut r) {
                    if tx.send((j, m)).is_err() {
                        break;
                    }
                }
            });
        }
        // sender threads: messages leave after the emulated one-way delay
        // (--delay-ms, 0 by default), in order, without blocking the caller
        let mut out = BTreeMap::new();
        for (&j, s) in &peers {
            let mut w = s.lock().unwrap().try_clone().unwrap();
            let (otx, orx) = channel::<(Instant, Vec<u8>)>();
            thread::spawn(move || {
                while let Ok((at, bytes)) = orx.recv() {
                    precise_wait_until(at);
                    let len = (bytes.len() as u32).to_le_bytes();
                    if w.write_all(&len).and_then(|_| w.write_all(&bytes)).is_err() {
                        break;
                    }
                }
            });
            out.insert(j, otx);
        }
        Network { me, peers, out, delay: Duration::from_secs_f64(delay_ms / 1000.0), rx, self_tx: tx, bytes_sent: 0 }
    }

    fn send(&mut self, to: u8, m: Net) {
        if to == self.me {
            self.self_tx.send((to, m)).unwrap();
        } else {
            let bytes = postcard::to_allocvec(&m).expect("serialize");
            self.bytes_sent += bytes.len() + 4;
            self.out[&to].send((Instant::now() + self.delay, bytes)).expect("sender thread");
        }
    }

    fn recv(&self) -> (u8, Net) {
        self.rx.recv().expect("all connections closed")
    }
}

/// Waits until `at` with sub-millisecond accuracy: a coarse sleep up to
/// 2 ms before the deadline, then a spin-wait. Plain sleeps on Windows can
/// overshoot by 15 ms or more when the process is throttled (power saving,
/// background window), which made the emulated delay unstable.
fn precise_wait_until(at: Instant) {
    let margin = Duration::from_millis(2);
    loop {
        let now = Instant::now();
        if now >= at {
            return;
        }
        let left = at - now;
        if left > margin {
            thread::sleep(left - margin);
        } else {
            std::hint::spin_loop();
        }
    }
}

#[cfg(windows)]
#[link(name = "winmm")]
extern "system" {
    fn timeBeginPeriod(period: u32) -> u32;
}

/// Asks Windows for a 1 ms timer resolution (default: 15.6 ms).
fn high_resolution_timers() {
    #[cfg(windows)]
    unsafe {
        timeBeginPeriod(1);
    }
}

// ===========================================================================
// Key material (dealer with fixed seed, cached on disk for CGGMP)
// ===========================================================================

fn verifier(id: u8) -> TestVerifier {
    TestSigner::new(id).verifying_key()
}

fn party_id(v: &TestVerifier) -> u8 {
    let s = format!("{v:?}");
    s.trim_start_matches("TestVerifier(").trim_end_matches(')').parse().unwrap_or(0)
}

fn fingerprint(bytes: &[u8]) -> [u8; 8] {
    let h = Sha256::digest(bytes);
    h[..8].try_into().unwrap()
}

struct FrostKeys {
    key: frost::keys::KeyPackage,
    pubkeys: frost::keys::PublicKeyPackage,
    fp: [u8; 8],
}

fn frost_keys(me: u8, t: usize, n: usize) -> FrostKeys {
    let mut rng = ChaCha20Rng::seed_from_u64(SEED ^ ((t as u64) << 8) ^ n as u64);
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(n as u16, t as u16, frost::keys::IdentifierList::Default, &mut rng).unwrap();
    let my_id = frost::Identifier::try_from(me as u16 + 1).unwrap();
    let key = frost::keys::KeyPackage::try_from(shares[&my_id].clone()).unwrap();
    let fp = fingerprint(&pubkeys.verifying_key().serialize().unwrap());
    FrostKeys { key, pubkeys, fp }
}

#[derive(Serialize, Deserialize)]
struct CggmpCache {
    share: ThresholdKeyShare<Params, TestVerifier>,
    aux: AuxInfo<Params, TestVerifier>,
}

struct CggmpKeys {
    share: ThresholdKeyShare<Params, TestVerifier>,
    aux: AuxInfo<Params, TestVerifier>,
    fp: [u8; 8],
}

fn cggmp_keys(me: u8, t: usize, n: usize) -> CggmpKeys {
    let path = format!("cggmp_keys_t{t}_n{n}_node{me}.bin");
    let cache: CggmpCache = match fs::read(&path).ok().and_then(|b| postcard::from_bytes(&b).ok()) {
        Some(c) => {
            println!("  loaded key material from {path}");
            c
        }
        None => {
            println!("  generating CGGMP key material for ({t},{n}) with the shared seed (Paillier keys: about a minute, done once)...");
            let t0 = Instant::now();
            let ids: BTreeSet<TestVerifier> = (0..n as u8).map(verifier).collect();
            let mut rng = ChaCha20Rng::seed_from_u64(SEED ^ ((t as u64) << 8) ^ n as u64);
            let shares = ThresholdKeyShare::<Params, TestVerifier>::new_centralized(&mut rng, &ids, t, None).unwrap();
            let aux = AuxInfo::<Params, TestVerifier>::new_centralized(&mut rng, &ids);
            let v = verifier(me);
            let c = CggmpCache { share: shares[&v].clone(), aux: aux[&v].clone() };
            fs::write(&path, postcard::to_allocvec(&c).unwrap()).ok();
            println!("  done in {:.1} s, cached in {path}", t0.elapsed().as_secs_f64());
            c
        }
    };
    let vk = cache.share.verifying_key().unwrap();
    let fp = fingerprint(&vk.to_encoded_point(true).as_bytes().to_vec());
    CggmpKeys { share: cache.share, aux: cache.aux, fp }
}

// ===========================================================================
// Signer side
// ===========================================================================

struct CggmpRun {
    session: Option<Session<CggmpProto, SP>>,
    accum: Option<RoundAccumulator<CggmpProto, SP>>,
    started: Instant,
    online_from: Option<Instant>,
    cpu: Duration,
    done: bool,
}

struct Signer {
    me: u8,
    t: usize,
    frost: Option<FrostKeys>,
    cggmp: Option<CggmpKeys>,
    frost_nonces: HashMap<u32, frost::round1::SigningNonces>,
    runs: HashMap<u32, CggmpRun>,
    early: HashMap<u32, Vec<(u8, Vec<u8>)>>, // MPC messages received before Start
    finished: HashSet<u32>,
}

impl Signer {
    fn signers(&self) -> Vec<u8> {
        (0..self.t as u8).collect()
    }

    fn on_start(&mut self, net: &mut Network, seq: u32, digest: [u8; 32]) {
        if (self.me as usize) >= self.t {
            return;
        }
        if let Some(fk) = &self.frost {
            let (nonces, cm) = frost::round1::commit(fk.key.signing_share(), &mut OsRng);
            self.frost_nonces.insert(seq, nonces);
            net.send(0, Net::FrostCommit { seq, data: cm.serialize().unwrap() });
            return;
        }
        let ck = self.cggmp.as_ref().unwrap();
        let t0 = Instant::now();
        let selected: BTreeSet<TestVerifier> = self.signers().into_iter().map(verifier).collect();
        let ks = ck.share.to_key_share(&selected).unwrap();
        let aux = ck.aux.clone().subset(&selected).unwrap();
        let msg: k256::FieldBytes = digest.into();
        let ep = InteractiveSigning::<Params, TestVerifier>::new(msg, ks, aux).unwrap();
        let sid = SessionId::from_seed::<SP>(&[b"net-bench".as_slice(), &seq.to_le_bytes()].concat());
        let session = Session::<_, SP>::new(&mut OsRng, sid, TestSigner::new(self.me), ep).expect("session");
        let accum = session.make_accumulator();
        let mut run = CggmpRun {
            session: Some(session),
            accum: Some(accum),
            started: t0,
            online_from: None,
            cpu: Duration::ZERO,
            done: false,
        };
        // first-round messages
        {
            let session = run.session.as_ref().unwrap();
            let accum = run.accum.as_mut().unwrap();
            let dests: Vec<_> = session.message_destinations().iter().cloned().collect();
            for d in dests {
                let (m, art) = session.make_message(&mut OsRng, &d).expect("message");
                session.add_artifact(accum, art).expect("artifact");
                net.send(party_id(&d), Net::Mpc { seq, data: postcard::to_allocvec(&m).unwrap() });
            }
        }
        run.cpu += t0.elapsed();
        self.runs.insert(seq, run);
        self.advance(net, seq, Duration::ZERO);
        for (from, data) in self.early.remove(&seq).unwrap_or_default() {
            self.on_mpc(net, seq, from, data);
        }
    }

    fn on_precompute(&mut self, net: &mut Network, start: u32, count: u32) {
        if (self.me as usize) >= self.t {
            return;
        }
        let fk = self.frost.as_ref().unwrap();
        for seq in start..start + count {
            let (nonces, cm) = frost::round1::commit(fk.key.signing_share(), &mut OsRng);
            self.frost_nonces.insert(seq, nonces);
            net.send(0, Net::FrostCommit { seq, data: cm.serialize().unwrap() });
        }
    }

    fn on_frost_pkg(&mut self, net: &mut Network, seq: u32, data: Vec<u8>) {
        let fk = self.frost.as_ref().unwrap();
        let pkg = frost::SigningPackage::deserialize(&data).unwrap();
        let nonces = self.frost_nonces.remove(&seq).unwrap();
        let share = frost::round2::sign(&pkg, &nonces, &fk.key).unwrap();
        net.send(0, Net::FrostShare { seq, data: share.serialize() });
    }

    fn on_mpc(&mut self, net: &mut Network, seq: u32, from: u8, data: Vec<u8>) {
        if self.finished.contains(&seq) {
            return;
        }
        if !self.runs.contains_key(&seq) {
            self.early.entry(seq).or_default().push((from, data));
            return;
        }
        let t0 = Instant::now();
        {
            let run = self.runs.get_mut(&seq).unwrap();
            if run.done {
                return;
            }
            let session = run.session.as_ref().unwrap();
            let accum = run.accum.as_mut().unwrap();
            let m: Message<TestVerifier> = postcard::from_bytes(&data).expect("mpc message");
            let pre = session.preprocess_message(accum, &verifier(from), m).expect("preprocess");
            if let Some(verified) = pre.ok() {
                let processed = session.process_message(verified);
                session.add_processed_message(accum, processed).expect("add");
            }
        }
        self.advance(net, seq, t0.elapsed());
    }

    /// Finalizes rounds while possible, sends the next messages, and reports
    /// to the coordinator when the protocol finishes.
    fn advance(&mut self, net: &mut Network, seq: u32, extra_cpu: Duration) {
        let t0 = Instant::now();
        let run = self.runs.get_mut(&seq).unwrap();
        loop {
            let session = run.session.take().unwrap();
            let accum = run.accum.take().unwrap();
            match session.can_finalize(&accum) {
                CanFinalize::NotYet => {
                    run.session = Some(session);
                    run.accum = Some(accum);
                    break;
                }
                CanFinalize::Never => panic!("CGGMP session {seq} cannot finish"),
                CanFinalize::Yes => match session.finalize_round(&mut OsRng, accum).expect("finalize") {
                    RoundOutcome::Finished(report) => {
                        let ok = matches!(report.outcome, SessionOutcome::Result(_));
                        run.done = true;
                        let end = Instant::now();
                        run.cpu += end - t0 + extra_cpu;
                        let online_from = run.online_from.unwrap_or(end);
                        net.send(
                            0,
                            Net::Done {
                                seq,
                                offline_us: (online_from - run.started).as_micros() as u64,
                                online_us: (end - online_from).as_micros() as u64,
                                cpu_us: run.cpu.as_micros() as u64,
                                ok,
                            },
                        );
                        return;
                    }
                    RoundOutcome::AnotherRound { session, cached_messages } => {
                        // CGGMP'24 presigning = rounds 1-3 (with echo rounds);
                        // the message-dependent signing round is round 4.
                        if session.round_id() == RoundId::new(4) && run.online_from.is_none() {
                            run.online_from = Some(Instant::now());
                        }
                        let mut accum = session.make_accumulator();
                        for m in cached_messages {
                            let p = session.process_message(m);
                            session.add_processed_message(&mut accum, p).expect("add cached");
                        }
                        let dests: Vec<_> = session.message_destinations().iter().cloned().collect();
                        for d in dests {
                            let (m, art) = session.make_message(&mut OsRng, &d).expect("message");
                            session.add_artifact(&mut accum, art).expect("artifact");
                            net.send(party_id(&d), Net::Mpc { seq, data: postcard::to_allocvec(&m).unwrap() });
                        }
                        run.session = Some(session);
                        run.accum = Some(accum);
                    }
                },
            }
        }
        run.cpu += t0.elapsed() + extra_cpu;
    }
}

// ===========================================================================
// Coordinator side (node 0)
// ===========================================================================

#[derive(Default)]
struct Inbox {
    commits: BTreeMap<u32, BTreeMap<u8, Vec<u8>>>,
    shares: BTreeMap<u32, BTreeMap<u8, Vec<u8>>>,
    done: BTreeMap<u32, BTreeMap<u8, (u64, u64, u64, bool)>>,
    pongs: BTreeMap<u32, Instant>,
}

/// Handles one incoming message. Returns false on Quit.
fn pump(net: &mut Network, signer: &mut Signer, inbox: &mut Inbox) -> bool {
    let (from, m) = net.recv();
    match m {
        Net::Ping { k } => net.send(from, Net::Pong { k }),
        Net::Pong { k } => {
            inbox.pongs.insert(k, Instant::now());
        }
        Net::Start { seq, digest } => signer.on_start(net, seq, digest),
        Net::Precompute { start, count } => signer.on_precompute(net, start, count),
        Net::FrostPkg { seq, data } => signer.on_frost_pkg(net, seq, data),
        Net::Mpc { seq, data } => signer.on_mpc(net, seq, from, data),
        Net::FrostCommit { seq, data } => {
            inbox.commits.entry(seq).or_default().insert(from, data);
        }
        Net::FrostShare { seq, data } => {
            inbox.shares.entry(seq).or_default().insert(from, data);
        }
        Net::Done { seq, offline_us, online_us, cpu_us, ok } => {
            inbox.done.entry(seq).or_default().insert(from, (offline_us, online_us, cpu_us, ok));
        }
        Net::Quit => return false,
        Net::Hello { .. } => {}
    }
    true
}

fn median(v: &[f64]) -> f64 {
    let mut s: Vec<f64> = v.iter().cloned().filter(|x| !x.is_nan()).collect();
    s.sort_by(|a, b| a.total_cmp(b));
    if s.is_empty() {
        return f64::NAN;
    }
    let m = s.len() / 2;
    if s.len() % 2 == 1 { s[m] } else { (s[m - 1] + s[m]) / 2.0 }
}

fn quantile(v: &[f64], q: f64) -> f64 {
    let mut s: Vec<f64> = v.iter().cloned().filter(|x| !x.is_nan()).collect();
    s.sort_by(|a, b| a.total_cmp(b));
    if s.is_empty() {
        return f64::NAN;
    }
    let pos = q * (s.len() - 1) as f64;
    let (lo, hi) = (pos.floor() as usize, pos.ceil() as usize);
    s[lo] + (s[hi] - s[lo]) * (pos - lo as f64)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn coordinator(args: &Args, n: usize, net: &mut Network, signer: &mut Signer) {
    let mut inbox = Inbox::default();
    let peers: Vec<u8> = (1..n as u8).collect();

    // 1. Round-trip times to every peer
    println!("measuring round-trip times ({} pings per node)...", args.pings);
    let mut rtt: BTreeMap<u8, Vec<f64>> = BTreeMap::new();
    let mut k = 0u32;
    for &p in &peers {
        for _ in 0..args.pings {
            k += 1;
            let t0 = Instant::now();
            net.send(p, Net::Ping { k });
            while !inbox.pongs.contains_key(&k) {
                pump(net, signer, &mut inbox);
            }
            rtt.entry(p).or_default().push(ms(inbox.pongs[&k] - t0));
            thread::sleep(Duration::from_millis(10));
        }
    }
    let signer_ids: Vec<u8> = (0..args.t as u8).collect();
    let max_rtt_signers = signer_ids
        .iter()
        .filter(|&&p| p != 0)
        .map(|p| median(&rtt[p]))
        .fold(0.0, f64::max);
    for (p, v) in &rtt {
        println!("  node {p}: median RTT {:.2} ms", median(v));
    }

    // 2. Signatures
    let total = args.warmup + args.count;
    println!("signing: {} warm-up + {} measured, protocol {}, ({},{})", args.warmup, args.count, args.proto, args.t, n);
    fs::create_dir_all(&args.out).ok();
    let path = format!("{}/{}_{}_t{}_n{}.csv", args.out, args.label, args.proto, args.t, n);
    let mut csv = BufWriter::new(fs::File::create(&path).unwrap());
    writeln!(csv, "label,proto,t,n,seq,latency_ms,cpu_max_ms,offline_ms,online_ms").unwrap();
    let mut lat = Vec::new();
    let mut cpu = Vec::new();
    let mut off = Vec::new();
    let mut on = Vec::new();
    if args.proto == "frost-pre" {
        // offline phase (not timed): every signer publishes one commitment per future signature
        println!("preprocessing: collecting {total} commitments per signer...");
        for &s in &signer_ids {
            net.send(s, Net::Precompute { start: 0, count: total as u32 });
        }
        while (0..total as u32).any(|q| inbox.commits.get(&q).map_or(0, |m| m.len()) < args.t) {
            pump(net, signer, &mut inbox);
        }
    }
    for seq in 0..total as u32 {
        let mut digest = [0u8; 32];
        OsRng.fill_bytes(&mut digest);
        let t0 = Instant::now();
        let (cpu_ms, off_ms, on_ms);
        if args.proto.starts_with("frost") {
            if args.proto == "frost" {
                for &s in &signer_ids {
                    net.send(s, Net::Start { seq, digest });
                }
            }
            while inbox.commits.get(&seq).map_or(0, |m| m.len()) < args.t {
                pump(net, signer, &mut inbox);
            }
            let tc = Instant::now();
            let commits: BTreeMap<_, _> = inbox.commits.remove(&seq).unwrap()
                .into_iter()
                .map(|(i, b)| {
                    (frost::Identifier::try_from(i as u16 + 1).unwrap(),
                     frost::round1::SigningCommitments::deserialize(&b).unwrap())
                })
                .collect();
            let pkg = frost::SigningPackage::new(commits, &digest);
            let data = pkg.serialize().unwrap();
            let mut coord = tc.elapsed();
            for &s in &signer_ids {
                net.send(s, Net::FrostPkg { seq, data: data.clone() });
            }
            while inbox.shares.get(&seq).map_or(0, |m| m.len()) < args.t {
                pump(net, signer, &mut inbox);
            }
            let ta = Instant::now();
            let shares: BTreeMap<_, _> = inbox.shares.remove(&seq).unwrap()
                .into_iter()
                .map(|(i, b)| {
                    (frost::Identifier::try_from(i as u16 + 1).unwrap(),
                     frost::round2::SignatureShare::deserialize(&b).unwrap())
                })
                .collect();
            let fk = signer.frost.as_ref().unwrap();
            let sig = frost::aggregate(&pkg, &shares, &fk.pubkeys).expect("aggregate");
            fk.pubkeys.verifying_key().verify(&digest, &sig).expect("FROST signature must verify");
            coord += ta.elapsed();
            cpu_ms = ms(coord);
            off_ms = f64::NAN;
            on_ms = f64::NAN;
        } else {
            for &s in &signer_ids {
                net.send(s, Net::Start { seq, digest });
            }
            while inbox.done.get(&seq).map_or(0, |m| m.len()) < args.t {
                pump(net, signer, &mut inbox);
            }
            let d = inbox.done.remove(&seq).unwrap();
            assert!(d.values().all(|x| x.3), "a CGGMP session failed");
            cpu_ms = d.values().map(|x| x.2 as f64 / 1000.0).fold(0.0, f64::max);
            off_ms = d.values().map(|x| x.0 as f64 / 1000.0).fold(0.0, f64::max);
            on_ms = d.values().map(|x| x.1 as f64 / 1000.0).fold(0.0, f64::max);
            signer.runs.remove(&seq);
            signer.finished.insert(seq);
        }
        let l = ms(t0.elapsed());
        if seq as usize >= args.warmup {
            writeln!(csv, "{},{},{},{},{},{:.3},{:.3},{:.3},{:.3}", args.label, args.proto, args.t, n,
                     seq as usize - args.warmup, l, cpu_ms, off_ms, on_ms).unwrap();
            lat.push(l);
            cpu.push(cpu_ms);
            off.push(off_ms);
            on.push(on_ms);
        }
        if (seq as usize + 1) % (total / 10).max(1) == 0 {
            println!("  {}/{} (last latency {:.1} ms)", seq + 1, total, l);
        }
    }
    csv.flush().unwrap();
    for &p in &peers {
        net.send(p, Net::Quit);
    }

    // 3. Summary, with the analytic model of the journal article:
    //    latency = CPU on the critical path + one-way delay x sequential steps.
    //    Steps counted here include the request (Start) and, for CGGMP, the
    //    final report (Done): FROST 1+3 = 4, FROST with preprocessing 2
    //    (signing package, shares), CGGMP 1+7+1 = 9.
    let steps = match args.proto.as_str() { "frost" => 4.0, "frost-pre" => 2.0, _ => 9.0 };
    let one_way = max_rtt_signers / 2.0;
    let summary = format!("{}/summary.csv", args.out);
    let new = !std::path::Path::new(&summary).exists();
    let mut s = fs::OpenOptions::new().create(true).append(true).open(&summary).unwrap();
    if new {
        writeln!(s, "label,proto,t,n,samples,rtt_ms,latency_median_ms,latency_q1_ms,latency_q3_ms,latency_p90_ms,cpu_median_ms,offline_median_ms,online_median_ms,model_ms").unwrap();
    }
    let lm = median(&lat);
    let model = median(&cpu).max(0.0) + steps * one_way;
    writeln!(s, "{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
             args.label, args.proto, args.t, n, lat.len(), max_rtt_signers, lm,
             quantile(&lat, 0.25), quantile(&lat, 0.75), quantile(&lat, 0.9),
             median(&cpu), median(&off), median(&on), model).unwrap();
    println!();
    println!("RESULT {} ({},{}) on '{}': median latency {:.2} ms [Q1 {:.2}, Q3 {:.2}], RTT {:.2} ms",
             args.proto, args.t, n, args.label, lm, quantile(&lat, 0.25), quantile(&lat, 0.75), max_rtt_signers);
    if args.proto == "cggmp" {
        println!("       presigning (rounds 1-3) {:.1} ms, online signing (round 4) {:.1} ms",
                 median(&off), median(&on));
    }
    println!("       written to {path} and {summary}");
}

// ===========================================================================
// main
// ===========================================================================

fn main() {
    let args = parse_args();
    high_resolution_timers();
    let cfg = read_config(&args.config);
    let n = cfg.len();
    assert!(args.t >= 2 && args.t <= n, "need 2 <= t <= n");
    assert!(["frost", "frost-pre", "cggmp"].contains(&args.proto.as_str()), "--proto frost|frost-pre|cggmp");
    println!("node {} of {n}, protocol {}, threshold {}", args.id, args.proto, args.t);

    let (frost_k, cggmp_k, fp) = if args.proto.starts_with("frost") {
        let k = frost_keys(args.id, args.t, n);
        let fp = k.fp;
        (Some(k), None, fp)
    } else {
        let k = cggmp_keys(args.id, args.t, n);
        let fp = k.fp;
        (None, Some(k), fp)
    };
    println!("connecting...");
    let mut net = Network::connect(args.id, &cfg, fp, args.delay_ms);
    println!("all {} nodes connected", n);

    let mut signer = Signer {
        me: args.id,
        t: args.t,
        frost: frost_k,
        cggmp: cggmp_k,
        frost_nonces: HashMap::new(),
        runs: HashMap::new(),
        early: HashMap::new(),
        finished: HashSet::new(),
    };
    if args.id == 0 {
        coordinator(&args, n, &mut net, &mut signer);
        thread::sleep(Duration::from_millis(300));
    } else {
        let mut inbox = Inbox::default();
        while pump(&mut net, &mut signer, &mut inbox) {
            // finished CGGMP runs are no longer needed
            let done: Vec<u32> = signer.runs.iter().filter(|(_, r)| r.done).map(|(k, _)| *k).collect();
            for k in done {
                signer.runs.remove(&k);
                signer.finished.insert(k);
            }
        }
        println!("done (coordinator finished)");
    }
}
