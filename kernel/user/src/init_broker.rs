//! init as the spawn broker of a durable boot (docs/BROKER.md). The worker
//! has no spawn right; it asks here, over a channel init made, and init
//! starts what the embedded workflow policy permits, with handles init
//! chooses, as init's own child.

use absd_abi::program;
use absd_abi::syscall::SPAWN_NO_SPAWN;
use absd_user::broker::{
    Args, MAX_REQUEST_BYTES, MAX_STARTUP_BYTES, Parsed, REFUSED_MALFORMED, REFUSED_NOT_PERMITTED,
    REFUSED_RESOURCES, REFUSED_SLOT, REPLY_EXITED, REPLY_REFUSED, REPLY_STARTED, ROLE_BLOCK,
    ROLE_REPLY, ROLE_REQUEST, ROLE_SLOT_STDERR, ROLE_SLOT_STDIN, ROLE_SLOT_STDOUT, ROLE_STDERR,
    ROLE_STDIN, ROLE_STDOUT, encode_reply, parse_request, startup_record,
};
use absd_user::{
    Child, Console, Error, INFO_STATE_TERMINAL, Outcome, Pipe, RIGHT_READ, RIGHT_WRITE,
    SpawnHandleCopy, close, duplicate, info, kill, spawn_many_copy, wait_timeout,
};

const POLICY: &str = include_str!(env!("ABSD_BROKER_POLICY_EMBED"));
const MAX_REQUESTERS: usize = 4;
const MAX_SLOTS: usize = 4;
const MAX_BROKERED: usize = 8;
const MAX_FIXED_ARGS: usize = 16;
/// Handles a requester's channel adds to its startup vector.
pub const CHANNEL_HANDLES: usize = 2 + 3 * MAX_SLOTS;

/// Whether this build embeds a workflow policy, and so runs the broker.
pub fn enabled() -> bool {
    !POLICY.trim().is_empty()
}

/// One permitted edge of the policy, borrowed from the policy text.
struct Rule<'a> {
    requester: &'a str,
    path: &'a str,
    program: u64,
    block: bool,
    free: usize,
    fixed: [&'a str; MAX_FIXED_ARGS],
    fixed_count: usize,
}

fn program_named(name: &str) -> Option<u64> {
    program::OWNERS
        .iter()
        .copied()
        .find(|&index| program::NAMES[index as usize] == name)
}

fn parse_rule(line: &str) -> Result<Option<Rule<'_>>, &'static str> {
    let mut words = line.split_ascii_whitespace();
    if words.next() != Some("allow") {
        return Ok(None);
    }
    let requester = words.next().ok_or("broker policy requester")?;
    let path = words.next().ok_or("broker policy path")?;
    let program = program_named(words.next().ok_or("broker policy program")?)
        .ok_or("broker policy names a program that is not an owner")?;
    let block = match words.next() {
        Some("none") => false,
        Some("read") => true,
        _ => return Err("broker policy block rights"),
    };
    let free = words
        .next()
        .and_then(|word| word.parse().ok())
        .ok_or("broker policy free argument count")?;
    let mut fixed = [""; MAX_FIXED_ARGS];
    let mut fixed_count = 0;
    for word in words {
        *fixed
            .get_mut(fixed_count)
            .ok_or("broker policy fixed arguments")? = word;
        fixed_count += 1;
    }
    Ok(Some(Rule {
        requester,
        path,
        program,
        block,
        free,
        fixed,
        fixed_count,
    }))
}

/// The slot count policy gives `requester`, if it may request at all.
fn slots_for(requester: &str) -> Result<Option<usize>, &'static str> {
    for line in POLICY.lines() {
        let mut words = line.split_ascii_whitespace();
        if words.next() == Some("slots") && words.next() == Some(requester) {
            let count: usize = words
                .next()
                .and_then(|word| word.parse().ok())
                .ok_or("broker policy slot count")?;
            if count == 0 || count > MAX_SLOTS {
                return Err("broker policy slot count out of range");
            }
            return Ok(Some(count));
        }
    }
    Ok(None)
}

/// Refuses a policy init could not apply exactly, before anything runs.
pub fn check_policy() -> Result<(), &'static str> {
    for line in POLICY.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_ascii_whitespace().next() {
            Some("allow") => {
                parse_rule(line)?;
            }
            Some("env") => {
                let mut words = line.split_ascii_whitespace().skip(1);
                program_named(words.next().unwrap_or(""))
                    .ok_or("broker policy env names a program that is not an owner")?;
                let pair = words.next().ok_or("broker policy env value")?;
                match pair.split_once('=') {
                    Some((key, _)) if !key.is_empty() => {}
                    _ => return Err("broker policy env value"),
                }
                if words.next().is_some() {
                    return Err("broker policy env line");
                }
            }
            Some("slots") => {
                let requester = line.split_ascii_whitespace().nth(1).unwrap_or("");
                slots_for(requester)?;
            }
            _ => return Err("broker policy line"),
        }
    }
    if slots_for("worker")?.is_none() {
        return Err("broker policy gives the worker no slots");
    }
    Ok(())
}

fn permitted<'a>(requester: &str, path: &[u8], args: &[u8]) -> Option<Rule<'a>>
where
    'static: 'a,
{
    for line in POLICY.lines() {
        let Ok(Some(rule)) = parse_rule(line) else {
            continue;
        };
        if rule.requester != requester || rule.path.as_bytes() != path {
            continue;
        }
        let mut given = Args::new(args);
        if given.argc() != rule.fixed_count + rule.free {
            continue;
        }
        if rule.fixed[..rule.fixed_count]
            .iter()
            .all(|fixed| given.next() == Some(fixed.as_bytes()))
        {
            return Some(rule);
        }
    }
    None
}

#[derive(Clone, Copy)]
struct Slot {
    /// init's ends: the child's stdin reader and stdout/stderr writers.
    stdin: u64,
    stdout: u64,
    stderr: u64,
    spent: bool,
}

impl Slot {
    const EMPTY: Self = Self {
        stdin: 0,
        stdout: 0,
        stderr: 0,
        spent: true,
    };
}

struct Requester {
    active: bool,
    /// Whether init still reads requests from it.
    open: bool,
    name: &'static str,
    /// The process that holds the other end: its requests are served only
    /// while it lives.
    owner: Child,
    request: Pipe,
    reply: Pipe,
    slots: [Slot; MAX_SLOTS],
    slot_count: usize,
    buffer: [u8; MAX_REQUEST_BYTES],
    length: usize,
}

impl Requester {
    const EMPTY: Self = Self {
        active: false,
        open: false,
        name: "",
        owner: Child::from_raw(0),
        request: Pipe::from_raw(0),
        reply: Pipe::from_raw(0),
        slots: [Slot::EMPTY; MAX_SLOTS],
        slot_count: 0,
        buffer: [0; MAX_REQUEST_BYTES],
        length: 0,
    };
}

#[derive(Clone, Copy)]
struct Brokered {
    active: bool,
    child: Child,
    pid: u64,
    requester: usize,
    slot: u8,
    /// The channel this child itself requests on, if policy gives it one.
    channel: Option<usize>,
}

impl Brokered {
    const EMPTY: Self = Self {
        active: false,
        child: Child::from_raw(0),
        pid: 0,
        requester: 0,
        slot: 0,
        channel: None,
    };
}

#[derive(Default, Clone, Copy)]
pub struct Stats {
    pub requests: u64,
    /// Requests whose requester had already ended: never served.
    pub dropped: u64,
    pub started: u64,
    pub refused: u64,
    pub exited: u64,
    pub reclaimed: u64,
}

struct Broker {
    requesters: [Requester; MAX_REQUESTERS],
    brokered: [Brokered; MAX_BROKERED],
    block: u64,
    stats: Stats,
}

static mut BROKER: Broker = Broker {
    requesters: [const { Requester::EMPTY }; MAX_REQUESTERS],
    brokered: [Brokered::EMPTY; MAX_BROKERED],
    block: 0,
    stats: Stats {
        requests: 0,
        dropped: 0,
        started: 0,
        refused: 0,
        exited: 0,
        reclaimed: 0,
    },
};

fn broker() -> &'static mut Broker {
    // init is single-threaded and this is its only reference.
    unsafe { &mut *core::ptr::addr_of_mut!(BROKER) }
}

/// A pipe split into its read end and write end. A failure leaves nothing.
fn pipe_pair() -> Result<(u64, u64), &'static str> {
    let pipe = Pipe::create().map_err(|_| "broker pipe")?;
    let pair = duplicate(pipe.raw(), RIGHT_READ).and_then(|reader| {
        duplicate(pipe.raw(), RIGHT_WRITE)
            .map(|writer| (reader, writer))
            .inspect_err(|_| {
                let _ = close(reader);
            })
    });
    let _ = close(pipe.raw());
    pair.map_err(|_| "broker pipe split")
}

/// The handles one requester's child side receives, and their roles.
pub struct ChannelEnds {
    pub requester: usize,
    pub handles: [u64; CHANNEL_HANDLES],
    pub roles: [u8; CHANNEL_HANDLES],
    pub count: usize,
}

impl ChannelEnds {
    /// No channel: a worker started with a startup record but no broker.
    pub const fn empty() -> Self {
        Self {
            requester: 0,
            handles: [0; CHANNEL_HANDLES],
            roles: [0; CHANNEL_HANDLES],
            count: 0,
        }
    }

    pub fn close(&self) {
        for &handle in &self.handles[..self.count] {
            let _ = close(handle);
        }
    }
}

/// Makes a channel and slots for a requester called `name` (a policy name).
/// A failure leaves no pipe behind: a requester that starves the pipe
/// table must not make init keep what it could not finish.
fn open_channel(name: &'static str, slots: usize) -> Result<ChannelEnds, &'static str> {
    let broker = broker();
    let index = broker
        .requesters
        .iter()
        .position(|requester| !requester.active)
        .ok_or("broker requesters exhausted")?;
    let mut ends = ChannelEnds {
        requester: index,
        handles: [0; CHANNEL_HANDLES],
        roles: [0; CHANNEL_HANDLES],
        count: 0,
    };
    // init's ends, in the order the requester keeps them: request reader,
    // reply writer, then each slot's stdin reader, stdout and stderr writers.
    let mut own = [0u64; CHANNEL_HANDLES];
    let mut made = 0;
    let mut pair = |role: u8, child_end_is_reader: bool| -> Result<(), &'static str> {
        let (reader, writer) = pipe_pair()?;
        let (child, init) = if child_end_is_reader {
            (reader, writer)
        } else {
            (writer, reader)
        };
        own[made] = init;
        made += 1;
        ends.handles[ends.count] = child;
        ends.roles[ends.count] = role;
        ends.count += 1;
        Ok(())
    };
    let built = (|| {
        pair(ROLE_REQUEST, false)?;
        pair(ROLE_REPLY, true)?;
        for _ in 0..slots {
            pair(ROLE_SLOT_STDIN, false)?;
            pair(ROLE_SLOT_STDOUT, true)?;
            pair(ROLE_SLOT_STDERR, true)?;
        }
        Ok(())
    })();
    if let Err(error) = built {
        for &handle in own[..made].iter().chain(&ends.handles[..ends.count]) {
            let _ = close(handle);
        }
        return Err(error);
    }
    let requester = &mut broker.requesters[index];
    *requester = Requester::EMPTY;
    requester.name = name;
    requester.request = Pipe::from_raw(own[0]);
    requester.reply = Pipe::from_raw(own[1]);
    for slot in 0..slots {
        requester.slots[slot] = Slot {
            stdin: own[2 + 3 * slot],
            stdout: own[3 + 3 * slot],
            stderr: own[4 + 3 * slot],
            spent: false,
        };
    }
    requester.slot_count = slots;
    requester.active = true;
    requester.open = true;
    Ok(ends)
}

/// The worker's channel. `block` is the handle init narrows for children.
pub fn open_worker_channel(block: u64) -> Result<ChannelEnds, &'static str> {
    let slots = slots_for("worker")?.ok_or("broker policy gives the worker no slots")?;
    broker().block = block;
    open_channel("worker", slots)
}

/// Serves every open channel once and collects every ended child. Called on
/// each turn of init's loop while the worker lives.
pub fn service(console: Console) {
    for index in 0..MAX_REQUESTERS {
        if broker().requesters[index].active && broker().requesters[index].open {
            read_requests(console, index);
        }
    }
    for index in 0..MAX_BROKERED {
        let entry = broker().brokered[index];
        if !entry.active {
            continue;
        }
        let terminal = info(Some(entry.child)).map(|record| record.state);
        if terminal != Ok(INFO_STATE_TERMINAL) {
            continue;
        }
        let Ok(outcome) = wait_timeout(Some(entry.child), 1) else {
            continue;
        };
        broker().brokered[index].active = false;
        broker().stats.exited += 1;
        let status = status_of(outcome);
        let _ = console.line(format_args!(
            "BROKER EXITED pid={} slot={} status={status}\n",
            entry.pid, entry.slot
        ));
        reply(entry.requester, REPLY_EXITED, entry.slot, 0, status);
        if let Some(channel) = entry.channel {
            close_requester(console, channel);
        }
    }
}

fn status_of(outcome: Outcome) -> i64 {
    match outcome {
        Outcome::Exited(status) => status as i64,
        Outcome::Faulted { vector, .. } => -(vector as i64) - 1000,
        Outcome::Killed => -1,
    }
}

fn reply(requester: usize, kind: u8, slot: u8, code: u32, value: i64) {
    let requester = &mut broker().requesters[requester];
    if !requester.active || requester.reply.raw() == 0 {
        return;
    }
    let bytes = encode_reply(kind, slot, code, value);
    // The reply pipe holds 42 whole replies, and a write takes only what
    // fits. A requester that stops reading loses its channel rather than
    // stalling init: it reads every reply that was written whole (and at
    // most a fragment), then end-of-file, never a torn reply followed by
    // later ones. Init reads nothing more from it.
    if requester.reply.write_timeout(&bytes, 1) != Ok(bytes.len()) {
        let _ = close(requester.reply.raw());
        requester.reply = Pipe::from_raw(0);
        requester.open = false;
    }
}

fn read_requests(console: Console, index: usize) {
    let requester = &mut broker().requesters[index];
    let length = requester.length;
    match requester
        .request
        .read_timeout(&mut requester.buffer[length..], 1)
    {
        Ok(0) => {
            requester.open = false;
            return;
        }
        Ok(count) => requester.length += count,
        Err(Error::Timeout) => return,
        Err(_) => {
            requester.open = false;
            return;
        }
    }
    loop {
        let requester = &mut broker().requesters[index];
        if !requester.open {
            return;
        }
        match parse_request(&requester.buffer[..requester.length]) {
            Parsed::Incomplete => {
                if requester.length == MAX_REQUEST_BYTES {
                    refuse_malformed(console, index);
                }
                return;
            }
            Parsed::Malformed => {
                refuse_malformed(console, index);
                return;
            }
            Parsed::Request {
                length,
                slot,
                path,
                args,
            } => {
                let mut request = [0u8; MAX_REQUEST_BYTES];
                request[..length].copy_from_slice(&requester.buffer[..length]);
                requester.buffer.copy_within(length..requester.length, 0);
                requester.length -= length;
                broker().stats.requests += 1;
                handle(
                    console,
                    index,
                    slot,
                    &request[path.0..path.1],
                    &request[args..length],
                );
            }
        }
    }
}

/// A requester whose stream cannot be parsed is not read again.
fn refuse_malformed(console: Console, index: usize) {
    broker().requesters[index].open = false;
    broker().stats.refused += 1;
    let _ = console.line(format_args!(
        "BROKER REFUSED requester={} code={REFUSED_MALFORMED}\n",
        broker().requesters[index].name
    ));
    reply(index, REPLY_REFUSED, 0xff, REFUSED_MALFORMED, 0);
}

fn refuse(console: Console, index: usize, slot: u8, code: u32) {
    broker().stats.refused += 1;
    let _ = console.line(format_args!(
        "BROKER REFUSED requester={} slot={slot} code={code}\n",
        broker().requesters[index].name
    ));
    reply(index, REPLY_REFUSED, slot, code, 0);
}

/// Names the process behind a channel, once it exists.
pub fn set_owner(index: usize, owner: Child) {
    broker().requesters[index].owner = owner;
}

fn handle(console: Console, index: usize, slot: u8, path: &[u8], args: &[u8]) {
    let name = broker().requesters[index].name;
    let owner = broker().requesters[index].owner;
    if info(Some(owner)).map(|record| record.state) != Ok(absd_user::INFO_STATE_LIVE)
        && info(Some(owner)).map(|record| record.state) != Ok(absd_user::INFO_STATE_WAITING)
    {
        broker().requesters[index].open = false;
        broker().stats.dropped += 1;
        let _ = console.line(format_args!(
            "BROKER DROPPED requester={name} slot={slot} reason=requester-ended\n"
        ));
        return;
    }
    let usable = (slot as usize) < broker().requesters[index].slot_count
        && !broker().requesters[index].slots[slot as usize].spent;
    if !usable {
        return refuse(console, index, slot, REFUSED_SLOT);
    }
    let Some(rule) = permitted(name, path, args) else {
        return refuse(console, index, slot, REFUSED_NOT_PERMITTED);
    };
    match start(index, slot, &rule, args) {
        Ok((pid, _)) => {
            broker().stats.started += 1;
            let _ = console.line(format_args!(
                "BROKER STARTED requester={name} slot={slot} path={} program={} pid={pid} block={}\n",
                rule.path,
                program::NAMES[rule.program as usize],
                if rule.block { "read" } else { "none" }
            ));
            reply(index, REPLY_STARTED, slot, 0, pid as i64);
        }
        Err(_) => refuse(console, index, slot, REFUSED_RESOURCES),
    }
}

/// Starts the rule's program on `slot` of requester `index`. A failure
/// leaves the slot unspent and nothing else behind.
fn start(
    index: usize,
    slot: u8,
    rule: &Rule<'_>,
    args: &[u8],
) -> Result<(u64, usize), &'static str> {
    let entry = broker()
        .brokered
        .iter()
        .position(|entry| !entry.active)
        .ok_or("broker children exhausted")?;
    let ends = broker().requesters[index].slots[slot as usize];
    let (startup_reader, startup_writer) = pipe_pair()?;
    let mut copies = [SpawnHandleCopy::new(0, 0); 6 + CHANNEL_HANDLES];
    let mut roles = [(0u8, 0u8); 5 + CHANNEL_HANDLES];
    let mut count = 0;
    let mut role_count = 0;
    copies[count] = SpawnHandleCopy::new(startup_reader, RIGHT_READ);
    count += 1;
    copies[count] = SpawnHandleCopy::new(ends.stdin, RIGHT_READ);
    roles[role_count] = (ROLE_STDIN, count as u8);
    count += 1;
    role_count += 1;
    // stdout is the console; it is also named in the vector, so a
    // brokered child's vector is never mistaken for an older fixed shape.
    copies[count] = SpawnHandleCopy::new(ends.stdout, RIGHT_WRITE);
    roles[role_count] = (ROLE_STDOUT, count as u8);
    count += 1;
    role_count += 1;
    copies[count] = SpawnHandleCopy::new(ends.stderr, RIGHT_WRITE);
    roles[role_count] = (ROLE_STDERR, count as u8);
    count += 1;
    role_count += 1;
    let block = if rule.block {
        let narrowed = duplicate(broker().block, RIGHT_READ);
        let Ok(narrowed) = narrowed else {
            let _ = close(startup_reader);
            let _ = close(startup_writer);
            return Err("broker block handle");
        };
        copies[count] = SpawnHandleCopy::new(narrowed, RIGHT_READ);
        roles[role_count] = (ROLE_BLOCK, count as u8);
        count += 1;
        role_count += 1;
        narrowed
    } else {
        0
    };
    let requester_name = program::NAMES[rule.program as usize];
    let channel = match slots_for(requester_name) {
        Ok(Some(slots)) => match open_channel(requester_name, slots) {
            Ok(channel) => Some(channel),
            Err(error) => {
                let _ = close(startup_reader);
                let _ = close(startup_writer);
                if block != 0 {
                    let _ = close(block);
                }
                return Err(error);
            }
        },
        _ => None,
    };
    if let Some(channel) = &channel {
        for position in 0..channel.count {
            copies[count] = SpawnHandleCopy::new(
                channel.handles[position],
                if channel.roles[position] == ROLE_REQUEST
                    || channel.roles[position] == ROLE_SLOT_STDIN
                {
                    RIGHT_WRITE
                } else {
                    RIGHT_READ
                },
            );
            roles[role_count] = (channel.roles[position], count as u8);
            count += 1;
            role_count += 1;
        }
    }
    copies[count] = SpawnHandleCopy::console(ends.stdout, RIGHT_WRITE);
    count += 1;
    let spawned = spawn_many_copy(rule.program | SPAWN_NO_SPAWN, &copies[..count]);
    let _ = close(startup_reader);
    if block != 0 {
        let _ = close(block);
    }
    if let Some(channel) = &channel {
        channel.close();
    }
    let child = match spawned {
        Ok(child) => child,
        Err(_) => {
            let _ = close(startup_writer);
            if let Some(channel) = &channel {
                discard_requester(channel.requester);
            }
            return Err("broker spawn");
        }
    };
    // The slot is spent: init's copies of the child's ends go, so the child
    // is the only writer of its stdout and stderr and the requester sees
    // end-of-file exactly when it ends.
    let requester = &mut broker().requesters[index];
    requester.slots[slot as usize].spent = true;
    let _ = close(ends.stdin);
    let _ = close(ends.stdout);
    let _ = close(ends.stderr);
    let pid = info(Some(child)).map(|record| record.pid).unwrap_or(0);
    if let Some(channel) = &channel {
        set_owner(channel.requester, child);
    }
    broker().brokered[entry] = Brokered {
        active: true,
        child,
        pid,
        requester: index,
        slot,
        channel: channel.as_ref().map(|channel| channel.requester),
    };
    let mut record = [0u8; MAX_STARTUP_BYTES];
    let written = startup_record(&mut record, &roles[..role_count], args)
        .and_then(|length| append_env(&mut record, length, requester_name));
    if let Some(length) = written {
        let _ = Pipe::from_raw(startup_writer).write_all(&record[..length]);
    }
    let _ = close(startup_writer);
    Ok((pid, entry))
}

/// Appends the environment policy gives `program`, if any: its whole
/// environment, since nothing is inherited.
fn append_env(record: &mut [u8], length: usize, program: &str) -> Option<usize> {
    let pairs = || {
        POLICY.lines().filter_map(move |line| {
            let mut words = line.split_ascii_whitespace();
            (words.next() == Some("env") && words.next() == Some(program))
                .then(|| words.next())
                .flatten()
        })
    };
    let count = pairs().count();
    if count == 0 {
        return Some(length);
    }
    let mut writer = absd_user::broker::Writer::new(&mut record[length..]);
    writer.u16(count)?;
    for pair in pairs() {
        writer.u16(pair.len())?;
        writer.bytes(pair.as_bytes())?;
    }
    Some(length + writer.len())
}

/// Forgets a requester whose child never started.
fn discard_requester(index: usize) {
    let requester = &mut broker().requesters[index];
    let _ = close(requester.request.raw());
    if requester.reply.raw() != 0 {
        let _ = close(requester.reply.raw());
    }
    for slot in &requester.slots[..requester.slot_count] {
        if !slot.spent {
            let _ = close(slot.stdin);
            let _ = close(slot.stdout);
            let _ = close(slot.stderr);
        }
    }
    *requester = Requester::EMPTY;
}

/// The process behind requester `index` is gone: nothing it asked for may
/// outlive it. Every child started for it (and, through their channels,
/// for them) is killed and reaped, and its channel and slots are closed.
pub fn close_requester(console: Console, index: usize) {
    if !broker().requesters[index].active {
        return;
    }
    for entry in 0..MAX_BROKERED {
        let brokered = broker().brokered[entry];
        if !brokered.active || brokered.requester != index {
            continue;
        }
        let _ = kill(brokered.child);
        let outcome = wait_timeout(Some(brokered.child), 1000);
        broker().brokered[entry].active = false;
        broker().stats.reclaimed += 1;
        let _ = console.line(format_args!(
            "BROKER RECLAIMED pid={} slot={} outcome={}\n",
            brokered.pid,
            brokered.slot,
            outcome.map(status_of).unwrap_or(i64::MIN)
        ));
        if let Some(channel) = brokered.channel {
            close_requester(console, channel);
        }
    }
    discard_requester(index);
}

/// The worker ended: reclaim everything started for it.
pub fn close_worker(console: Console) {
    if let Some(index) = broker()
        .requesters
        .iter()
        .position(|requester| requester.active && requester.name == "worker")
    {
        close_requester(console, index);
    }
}

pub fn stats() -> Stats {
    broker().stats
}

/// Whether any brokered child is still recorded; after `close_requester`
/// for the worker there must be none.
pub fn idle() -> bool {
    broker().brokered.iter().all(|entry| !entry.active)
        && broker()
            .requesters
            .iter()
            .all(|requester| !requester.active)
}
