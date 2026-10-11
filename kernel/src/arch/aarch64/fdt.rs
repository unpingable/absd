//! Bounded QEMU virt device-tree reader, not a general hardware framework.
#[derive(Debug)]
pub struct Board {
    pub cpus: [u64; 4],
    pub cpu_count: usize,
    pub smp_request: usize,
    pub early_publication: bool,
    pub reset: bool,
    pub virtio: [u64; 32],
    pub virtio_count: usize,
    pub ram: (u64, u64),
    pub uart: u64,
    pub gicd: u64,
    pub gicc: u64,
    gicv2: bool,
    pub hvc: bool,
    pub dtb_bytes: usize,
}
fn word(b: &[u8], at: usize) -> Result<u32, &'static str> {
    Ok(u32::from_be_bytes(
        b.get(at..at + 4).ok_or("FDT bounds")?.try_into().unwrap(),
    ))
}
fn quad(b: &[u8], at: usize) -> Result<u64, &'static str> {
    Ok(u64::from_be_bytes(
        b.get(at..at + 8).ok_or("FDT bounds")?.try_into().unwrap(),
    ))
}
fn cstr(b: &[u8], at: usize) -> Result<&[u8], &'static str> {
    let s = b.get(at..).ok_or("FDT string bounds")?;
    Ok(&s[..s
        .iter()
        .position(|x| *x == 0)
        .ok_or("FDT unterminated string")?])
}
pub fn parse(b: &[u8]) -> Result<Board, &'static str> {
    if word(b, 0)? != 0xd00dfeed {
        return Err("FDT magic");
    }
    let size = word(b, 4)? as usize;
    if size > b.len() || size > 2 * 1024 * 1024 {
        return Err("FDT size");
    }
    let b = &b[..size];
    let structure = word(b, 8)? as usize;
    let strings = word(b, 12)? as usize;
    let end = structure
        .checked_add(word(b, 36)? as usize)
        .ok_or("FDT overflow")?;
    let string_end = strings
        .checked_add(word(b, 32)? as usize)
        .ok_or("FDT overflow")?;
    let names = b.get(strings..string_end).ok_or("FDT strings")?;
    if end > b.len() {
        return Err("FDT structure");
    }
    let mut board = Board {
        cpus: [0; 4],
        cpu_count: 0,
        smp_request: 0,
        early_publication: false,
        reset: false,
        virtio: [0; 32],
        virtio_count: 0,
        ram: (0, 0),
        uart: 0,
        gicd: 0,
        gicc: 0,
        gicv2: false,
        hvc: false,
        dtb_bytes: size,
    };
    let mut at = structure;
    let mut depth = 0usize;
    let mut nodes: [&[u8]; 32] = [b""; 32];
    let mut ended = false;
    while at < end {
        let token = word(b, at)?;
        at += 4;
        match token {
            1 => {
                if depth == 32 {
                    return Err("FDT depth");
                }
                let n = cstr(&b[..end], at)?;
                nodes[depth] = n;
                depth += 1;
                at = (at + n.len() + 1 + 3) & !3;
            }
            2 => {
                depth = depth.checked_sub(1).ok_or("FDT nesting")?;
            }
            3 => {
                let len = word(b, at)? as usize;
                let name = word(b, at + 4)? as usize;
                at += 8;
                let stop = at.checked_add(len).ok_or("FDT overflow")?;
                let data = b
                    .get(at..stop)
                    .filter(|_| stop <= end)
                    .ok_or("FDT property")?;
                at = (stop + 3) & !3;
                let key = cstr(names, name)?;
                let node = *nodes
                    .get(depth.checked_sub(1).ok_or("FDT property outside node")?)
                    .ok_or("FDT depth")?;
                if depth == 1
                    && (key == b"#address-cells" || key == b"#size-cells")
                    && word(data, 0)? != 2
                {
                    return Err("FDT unsupported root cells");
                }
                if node == b"chosen" && key == b"bootargs" {
                    for token in data.split(|c| *c == b' ' || *c == 0) {
                        if token == b"absd-arm-reset=1" {
                            board.reset = true;
                        }
                        if token == b"absd-arm-control=early-publication" {
                            board.early_publication = true;
                        }
                        if token.starts_with(b"absd-arm-smp=") {
                            if board.smp_request != 0 {
                                return Err("FDT duplicate SMP request");
                            }
                            board.smp_request = match token {
                                b"absd-arm-smp=2" => 2,
                                b"absd-arm-smp=4" => 4,
                                _ => return Err("FDT SMP request"),
                            };
                        }
                    }
                }
                if node.starts_with(b"intc@") && key == b"compatible" {
                    if !data
                        .split(|byte| *byte == 0)
                        .any(|name| name == b"arm,cortex-a15-gic")
                    {
                        return Err("FDT unsupported GIC version");
                    }
                    board.gicv2 = true;
                }
                if key == b"reg" {
                    if node.starts_with(b"cpu@") {
                        if board.cpu_count == 4 {
                            return Err("FDT CPU bound");
                        }
                        board.cpus[board.cpu_count] = match data.len() {
                            4 => word(data, 0)? as u64,
                            8 => quad(data, 0)?,
                            _ => return Err("FDT CPU reg"),
                        };
                        board.cpu_count += 1;
                    }
                    if node.starts_with(b"virtio_mmio@") {
                        if board.virtio_count == 32 {
                            return Err("FDT too many virtio transports");
                        }
                        board.virtio[board.virtio_count] = quad(data, 0)?;
                        board.virtio_count += 1;
                    }
                    if node.starts_with(b"memory@") {
                        if board.ram.1 != 0 || data.len() != 16 {
                            return Err("FDT RAM topology");
                        }
                        board.ram = (quad(data, 0)?, quad(data, 8)?);
                    }
                    if node.starts_with(b"pl011@") {
                        board.uart = quad(data, 0)?;
                    }
                    if node.starts_with(b"intc@") {
                        board.gicd = quad(data, 0)?;
                        board.gicc = quad(data, 16)?;
                    }
                }
                if node == b"psci" && key == b"method" {
                    board.hvc = data == b"hvc\0";
                }
            }
            4 => {}
            9 => {
                ended = true;
                break;
            }
            _ => return Err("FDT token"),
        }
    }
    if !ended
        || depth != 0
        || board.ram.1 == 0
        || board.uart == 0
        || board.gicd == 0
        || board.gicc == 0
        || !board.gicv2
        || !board.hvc
    {
        return Err("FDT required platform missing");
    }
    if board.ram.0 != 0x40000000 || board.ram.1 < 0x10000000 || board.uart != 0x09000000 {
        return Err("FDT unsupported virt layout");
    }
    if !matches!(board.cpu_count, 1 | 2 | 4) {
        return Err("FDT CPU topology");
    }
    board.cpus[..board.cpu_count].sort_unstable();
    if board.cpus[..board.cpu_count]
        .iter()
        .enumerate()
        .any(|(i, id)| *id != i as u64)
    {
        return Err("FDT CPU affinity topology");
    }
    Ok(board)
}
