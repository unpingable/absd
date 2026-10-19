//! Deferred, single-generation reconstruction after a verified clean retirement.
use super::*;

pub(super) const MAX_SUCCESSORS: u8 = 32;

pub(super) fn power_refused(port: u8) {
    let _ = writeln!(
        serial::Serial,
        "USB KEYBOARD PORT POWER REFUSED port={port} attempts={} window_ms={} until=decay",
        rules::PortPowerRetry::MAX_FAILURES,
        rules::PortPowerRetry::DECAY_TICKS
    );
}

#[derive(Clone, Copy, Debug)]
enum Step {
    Reset,
    ResetWait,
    Clear(usize),
    Scratch(u32),
    Program,
    Power(u8),
    PowerWait,
    Route,
    RunWait,
    Scan(u8),
    PortPowerWait(u8),
    PortWait,
    Enabled,
    Addressed,
    Prefix,
    Evaluated,
    Device,
    Header,
    Configuration,
    Configured,
    SetConfiguration,
    SetProtocol,
    GetProtocol,
    SetIdle,
    Disabled,
    Watch(u8),
    WatchPowerWait(u8),
}

struct Pending {
    wait: Wait,
    kind: u32,
    length: u16,
    short: Option<u32>,
    tick: u64,
    tsc: u64,
    irq: u64,
    uncredited: Option<u64>,
}

pub(super) struct Recovery {
    step: Step,
    pending: Option<Pending>,
    retired: xhci_irq::Snapshot,
    port: u8,
    speed: u8,
    length: u16,
    packet: u16,
    ports: [u16; 256],
    page_bytes: u64,
    fixture_reported: bool,
    enumeration_hold: Option<u64>,
    power_retry: Option<u8>,
}

/// The service supervisor consumes the old private runtime. Only the stable
/// Console service and service-owned PCI claim continue across this boundary.
pub(super) fn successor(mut old: Runtime) -> Runtime {
    assert_eq!(old.phase, Phase::Clean);
    assert!(old.recover && !old.shutdown && old.cleanable);
    assert!(old.successors < MAX_SUCCESSORS);
    let retired = old.quiet.unwrap().1;
    let previous = old.generation;
    old.controller.round = old.controller.round.checked_add(1).expect("bounded rounds");
    old.controller.failed = false;
    old.controller.armed_this_round = false;
    old.watch_power.advance(ticks());
    if let Some(port) = old.watch_power.successor() {
        power_refused(port);
    }
    let mut next = Runtime {
        controller: old.controller,
        keyboard: None,
        port: 0,
        slot: 0,
        ring: Producer::new(TRANSFER_RING_TRBS),
        outstanding: None,
        reports: Reports::new(),
        phase: Phase::Recovering,
        last_tick: old.last_tick,
        phase_tick: ticks(),
        phase_tsc: unsafe { core::arch::x86_64::_rdtsc() },
        irq_baseline: 0,
        generation: previous.checked_add(1).expect("bounded generations"),
        uncredited: None,
        quiet: None,
        cleanable: true,
        observe: old.observe,
        accepted_reports: 0,
        max_events: 0,
        test_race: false,
        race_deadline: None,
        race_done: false,
        last_report_tick: ticks(),
        idle_reported: false,
        recover: true,
        shutdown: false,
        successors: old.successors + 1,
        watch_power: old.watch_power,
        recovery: Some(Recovery {
            step: Step::Reset,
            pending: None,
            retired,
            port: 0,
            speed: 0,
            length: 0,
            packet: 0,
            ports: [0; 256],
            page_bytes: 0,
            fixture_reported: false,
            enumeration_hold: None,
            power_retry: None,
        }),
        recovery_test: old.recovery_test,
    };
    let _ = writeln!(
        serial::Serial,
        "USB KEYBOARD SUCCESSOR retired={previous} generation={} attempt={}",
        next.generation,
        next.successors
    );
    next.set_phase(Phase::Recovering);
    next
}

impl Recovery {
    /// The selected enumeration candidate, including before r.port is bound.
    /// Scan/power/watch phases have no current candidate or slot to charge.
    pub(super) fn current_port(&self) -> u8 {
        match self.step {
            Step::PortWait
            | Step::Enabled
            | Step::Addressed
            | Step::Prefix
            | Step::Evaluated
            | Step::Device
            | Step::Header
            | Step::Configuration
            | Step::Configured
            | Step::SetConfiguration
            | Step::SetProtocol
            | Step::GetProtocol
            | Step::SetIdle
            | Step::Disabled => self.port,
            Step::Reset
            | Step::ResetWait
            | Step::Clear(_)
            | Step::Scratch(_)
            | Step::Program
            | Step::Power(_)
            | Step::PowerWait
            | Step::Route
            | Step::RunWait
            | Step::Scan(_)
            | Step::PortPowerWait(_)
            | Step::Watch(_)
            | Step::WatchPowerWait(_) => 0,
        }
    }

    fn watching(&mut self, r: &mut Runtime) {
        if let Some(port) = r.watch_power.unbound() {
            power_refused(port);
        }
        r.set_phase(Phase::Watching);
        self.advance(r, Step::Watch(1));
    }

    pub(super) fn report_stop(&self, generation: u64) {
        let _ = writeln!(
            serial::Serial,
            "USB KEYBOARD RECOVERY STOP generation={generation} interrupted={:?}",
            self.step
        );
    }
    fn advance(&mut self, r: &mut Runtime, step: Step) {
        self.step = step;
        r.phase_tick = ticks();
        r.phase_tsc = unsafe { core::arch::x86_64::_rdtsc() };
        if r.observe {
            let _ = writeln!(
                serial::Serial,
                "USB KEYBOARD RECOVERY generation={} step={step:?}",
                r.generation
            );
        }
    }

    fn command(&mut self, r: &mut Runtime, trb: [u32; 4], next: Step) -> Result<(), XhciError> {
        assert!(self.pending.is_none());
        let c = &mut r.controller;
        c.ownership_holds()?;
        let ring = core::ptr::addr_of_mut!(COMMAND_RING);
        let claim = c.command.claim();
        write_trb(
            ring,
            claim.index,
            [trb[0], trb[1], trb[2], with_cycle(trb[3], claim.cycle)],
        );
        if let Some(cycle) = claim.link {
            write_trb(ring, c.command.link_index(), link_trb(ring, cycle));
        }
        let pointer = page(ring) + claim.index as u64 * rules::TRB_BYTES;
        self.pending = Some(Pending {
            wait: Wait::Command { trb: pointer },
            kind: rules::trb_type(trb[3]),
            length: 0,
            short: None,
            tick: ticks(),
            tsc: unsafe { core::arch::x86_64::_rdtsc() },
            irq: xhci_interrupt::STATE.credit_baseline(),
            uncredited: None,
        });
        c.ownership_holds()?;
        c.doorbell(0, 0);
        self.advance(r, next);
        Ok(())
    }

    fn control(
        &mut self,
        r: &mut Runtime,
        setup: u64,
        length: u16,
        next: Step,
    ) -> Result<(), XhciError> {
        assert!(self.pending.is_none());
        let c = &mut r.controller;
        c.ownership_holds()?;
        let buffer = page(core::ptr::addr_of_mut!(DATA));
        zero(core::ptr::addr_of_mut!(DATA));
        let (first, owned) = c.push_ep0(
            [
                setup as u32,
                (setup >> 32) as u32,
                8,
                rules::control(rules::TRB_SETUP)
                    | rules::TRB_IDT
                    | if length != 0 { rules::SETUP_IN_DATA } else { 0 },
            ],
            true,
        );
        let data = if length != 0 {
            c.push_ep0(
                [
                    buffer as u32,
                    (buffer >> 32) as u32,
                    u32::from(length),
                    rules::control(rules::TRB_DATA) | rules::DIRECTION_IN | rules::TRB_ISP,
                ],
                false,
            )
            .0
        } else {
            first
        };
        let (last, _) = c.push_ep0(
            [
                0,
                0,
                0,
                rules::control(rules::TRB_STATUS)
                    | rules::TRB_IOC
                    | if length == 0 { rules::DIRECTION_IN } else { 0 },
            ],
            false,
        );
        self.pending = Some(Pending {
            wait: Wait::Transfer {
                first,
                data,
                last,
                slot: r.slot,
                endpoint: EP0,
            },
            kind: 0,
            length,
            short: None,
            tick: ticks(),
            tsc: unsafe { core::arch::x86_64::_rdtsc() },
            irq: xhci_interrupt::STATE.credit_baseline(),
            uncredited: None,
        });
        c.ownership_holds()?;
        fence(Ordering::SeqCst);
        unsafe { core::ptr::write_volatile((first + 12) as *mut u32, owned) };
        c.doorbell(r.slot, u32::from(EP0));
        self.advance(r, next);
        Ok(())
    }

    fn poll(&mut self, r: &mut Runtime) -> Result<Option<u8>, XhciError> {
        let p = self.pending.as_mut().unwrap();
        let c = &mut r.controller;
        c.ownership_holds()?;
        xhci_interrupt::STATE
            .check()
            .map_err(XhciError::Interrupt)?;
        if xhci_interrupt::STATE.snapshot().generation != r.generation {
            return Err(XhciError::Interrupt(xhci_irq::Error::Drain));
        }
        if ticks().wrapping_sub(p.tick)
            > if p.kind == 0 {
                TRANSFER_TICKS
            } else {
                COMMAND_TICKS
            }
            || unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(p.tsc) > STOP_TSC
        {
            return Err(XhciError::Timeout("keyboard recovery transaction"));
        }
        if c.event_available() && xhci_interrupt::STATE.snapshot().count == p.irq {
            let start = *p.uncredited.get_or_insert_with(ticks);
            if ticks().wrapping_sub(start) > IRQ_WAIT_TICKS {
                return Err(XhciError::Interrupt(
                    xhci_irq::Error::CompletedWithoutInterrupt,
                ));
            }
            return Ok(None);
        }
        let ep0 = page(core::ptr::addr_of_mut!(EP0_RING));
        for _ in 0..PUMP_EVENTS {
            c.ownership_holds()?;
            let Some(event) = c.take_event()? else {
                return Ok(None);
            };
            match rules::judge(
                event,
                p.wait,
                (ep0, ep0 + c.ep0.link_index() as u64 * rules::TRB_BYTES),
            ) {
                Verdict::Complete {
                    code,
                    slot,
                    residual,
                } => {
                    if code != rules::COMPLETION_SUCCESS {
                        return Err(if p.kind != 0 {
                            XhciError::Command { kind: p.kind, code }
                        } else {
                            XhciError::Transfer { code }
                        });
                    }
                    if matches!(p.wait, Wait::Command { .. })
                        && !matches!(self.step, Step::Enabled)
                        && slot != r.slot
                    {
                        return Err(XhciError::SlotId(slot));
                    }
                    let residual = p.short.unwrap_or(residual);
                    if residual != 0 {
                        return Err(XhciError::Short {
                            expected: p.length,
                            got: u32::from(p.length).saturating_sub(residual),
                        });
                    }
                    self.pending = None;
                    return Ok(Some(slot));
                }
                Verdict::PortChange { port } if port != 0 && port <= c.layout.max_ports => {
                    let value = c.read32(c.portsc(port));
                    let previous = self.ports[usize::from(port)];
                    let current_changed = port == self.port
                        && rules::port_observation_changed(
                            previous,
                            value,
                            c.layout.port_power_control,
                        );
                    let earlier_changed = port < self.port
                        && !r.watch_power.blocked(port)
                        && rules::port_watch_changed(previous, value, c.layout.port_power_control);
                    if current_changed || earlier_changed {
                        let restored = port < self.port
                            && rules::port_watch_restored(
                                previous,
                                value,
                                c.layout.port_power_control,
                            );
                        if !restored || r.watch_power.reconstruct(port) {
                            let _ = writeln!(
                                serial::Serial,
                                "USB KEYBOARD ENUMERATION CHANGE port={port} scanned_through={}",
                                self.port
                            );
                            if port == self.port
                                && !rules::port_power_ready(value, c.layout.port_power_control)
                            {
                                r.fence_power(port, "scan port changed");
                            } else {
                                r.fence_input("scan port changed");
                            }
                            return Ok(None);
                        }
                    }
                    c.write32(
                        c.portsc(port),
                        rules::portsc_neutral(value) | (value & rules::PORTSC_CHANGES),
                    );
                    self.ports[usize::from(port)] =
                        rules::port_observation(value, c.layout.port_power_control);
                }
                Verdict::Short { residual } => p.short = Some(residual),
                _ => return Err(XhciError::Unexpected(event)),
            }
        }
        Ok(None)
    }

    fn bytes(&self, length: usize) -> [u8; hid::CONFIG_BYTES] {
        assert!(length <= hid::CONFIG_BYTES);
        fence(Ordering::SeqCst);
        let data = page(core::ptr::addr_of_mut!(DATA)) as *const u8;
        let mut bytes = [0; hid::CONFIG_BYTES];
        for (n, byte) in bytes[..length].iter_mut().enumerate() {
            *byte = unsafe { core::ptr::read_volatile(data.add(n)) };
        }
        bytes
    }

    fn context_command(&mut self, r: &mut Runtime, kind: u32, next: Step) -> Result<(), XhciError> {
        let input = page(core::ptr::addr_of_mut!(INPUT_CONTEXT));
        self.command(
            r,
            [
                input as u32,
                (input >> 32) as u32,
                0,
                rules::control(kind) | (u32::from(r.slot) << 24),
            ],
            next,
        )
    }

    fn device(&mut self, r: &mut Runtime) -> Result<(), XhciError> {
        self.control(r, rules::get_descriptor_setup(1, 0, 18), 18, Step::Device)
    }

    fn disable(&mut self, r: &mut Runtime) -> Result<(), XhciError> {
        self.command(
            r,
            [
                0,
                0,
                0,
                rules::control(rules::TRB_DISABLE_SLOT) | (u32::from(r.slot) << 24),
            ],
            Step::Disabled,
        )
    }

    pub(super) fn progress(&mut self, r: &mut Runtime) -> Result<(), XhciError> {
        r.controller.ownership_holds()?;
        if r.recovery_test == KeyboardRecoveryTest::EnumerationHold
            && matches!(self.step, Step::Disabled)
        {
            if !self.fixture_reported {
                self.fixture_reported = true;
                self.enumeration_hold = Some(ticks());
                let _ = writeln!(
                    serial::Serial,
                    "USB KEYBOARD RECOVERY FIXTURE enumeration-held port={} source=completion-defer",
                    self.port
                );
            }
            if let Some(start) = self.enumeration_hold {
                if ticks().wrapping_sub(start) < 200 {
                    return Ok(());
                }
                self.enumeration_hold = None;
                serial::write("USB KEYBOARD RECOVERY FIXTURE enumeration-released\n");
            }
        }
        if !matches!(self.step, Step::Reset | Step::ResetWait) {
            let status = r.controller.status();
            if status & (USBSTS_HOST_SYSTEM_ERROR | USBSTS_HOST_CONTROLLER_ERROR) != 0 {
                return Err(XhciError::ControllerError(status));
            }
        }
        let done = if self.pending.is_some() {
            let Some(slot) = self.poll(r)? else {
                return Ok(());
            };
            Some(slot)
        } else {
            None
        };
        if done.is_none()
            && !matches!(
                self.step,
                Step::Reset
                    | Step::ResetWait
                    | Step::Clear(_)
                    | Step::Scratch(_)
                    | Step::Program
                    | Step::Power(_)
                    | Step::PowerWait
                    | Step::Route
                    | Step::Watch(_)
                    | Step::WatchPowerWait(_)
            )
            && (ticks().wrapping_sub(r.phase_tick)
                > if matches!(self.step, Step::PortWait) {
                    PORT_RESET_TICKS
                } else {
                    HALT_TICKS
                }
                || unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(r.phase_tsc) > STOP_TSC)
        {
            return Err(XhciError::Timeout("keyboard recovery phase"));
        }
        match self.step {
            Step::Reset => {
                if r.successors == 1 && r.recovery_test == KeyboardRecoveryTest::LateEntry {
                    serial::write(
                        "USB KEYBOARD RECOVERY FIXTURE late-entry source=software-entry\n",
                    );
                    xhci_interrupt::inject_late_entry();
                }
                let c = &mut r.controller;
                if !c.halted()
                    || pci::bus_master(c.function)
                    || c.interrupt.as_ref().unwrap().pending()
                    || xhci_interrupt::STATE.snapshot() != self.retired
                {
                    return Err(XhciError::Keyboard(hid::Error::RetirementUncertain));
                }
                c.write32(c.operational(OP_USBCMD), USBCMD_RESET);
                self.advance(r, Step::ResetWait);
            }
            Step::ResetWait => {
                let substitute =
                    r.successors == 1 && r.recovery_test == KeyboardRecoveryTest::ResetTimeout;
                if substitute && !self.fixture_reported {
                    serial::write(
                        "USB KEYBOARD RECOVERY FIXTURE reset-pending source=observation-substitution\n",
                    );
                    self.fixture_reported = true;
                }
                let c = &mut r.controller;
                if c.read32(c.operational(OP_USBCMD)) & USBCMD_RESET != 0
                    || c.status() & USBSTS_NOT_READY != 0
                    || substitute
                {
                    if ticks().wrapping_sub(r.phase_tick) > READY_TICKS
                        || unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(r.phase_tsc)
                            > STOP_TSC
                    {
                        return Err(XhciError::Keyboard(hid::Error::ResetTimeout));
                    }
                    return Ok(());
                }
                if !(hid::Reclaim {
                    halted: c.halted(),
                    bus_master: pci::bus_master(c.function),
                    reset_complete: true,
                    irq_pending: c.interrupt.as_ref().unwrap().pending(),
                    quiet_unchanged: xhci_interrupt::STATE.snapshot() == self.retired,
                })
                .permitted()
                {
                    return Err(XhciError::Keyboard(hid::Error::RetirementUncertain));
                }
                c.release_scratchpads(true);
                if matches!(c.pool.state(), PoolState::Prepared { .. }) {
                    c.pool.abandon().map_err(|_| XhciError::Failed)?;
                }
                if !matches!(c.pool.state(), PoolState::Free) {
                    return Err(XhciError::Failed);
                }
                let page_size = c.read32(c.operational(OP_PAGESIZE));
                self.page_bytes =
                    scratch::page_bytes(page_size, c.scratchpads).map_err(|_| XhciError::Failed)?;
                if c.scratchpads != 0 {
                    c.pool
                        .prepare(c.scratchpads)
                        .map_err(|_| XhciError::Failed)?;
                }
                let _ = writeln!(
                    serial::Serial,
                    "USB KEYBOARD RECLAIM generation={} reset=1 halted=1 dma_off=1",
                    r.generation
                );
                self.advance(r, Step::Clear(0));
            }
            Step::Clear(index) => {
                zero(pages()[index]);
                if index + 1 < pages().len() {
                    self.advance(r, Step::Clear(index + 1));
                } else {
                    self.advance(r, Step::Scratch(0));
                }
            }
            Step::Scratch(index) => {
                let c = &mut r.controller;
                if index < c.scratchpads {
                    let buffer = scratchpad(index as usize);
                    scratch::check_page(
                        index,
                        page(buffer),
                        self.page_bytes,
                        self.page_bytes,
                        owned_range(),
                        c.layout.addresses_64,
                    )
                    .map_err(|error| XhciError::Refused(Refusal::Address(error)))?;
                    zero(buffer);
                    unsafe {
                        core::ptr::write_volatile(
                            (page(core::ptr::addr_of_mut!(SCRATCHPAD_ARRAY)) + 8 * u64::from(index))
                                as *mut u64,
                            page(buffer),
                        )
                    };
                    self.advance(r, Step::Scratch(index + 1));
                } else {
                    self.advance(r, Step::Program);
                }
            }
            Step::Program => {
                let c = &mut r.controller;
                // HCRST cleared old pointers and every successor page is now
                // initialized. Like the boot path, enable DMA before publishing
                // ERSTBA: a halted controller may fetch that table immediately.
                // The route remains disabled and Run clear until validation.
                if !c.halted() || xhci_interrupt::STATE.snapshot() != self.retired {
                    return Err(XhciError::Keyboard(hid::Error::RetirementUncertain));
                }
                c.bus_master_on();
                c.armed_this_round = true;
                c.command = Producer::new(COMMAND_RING_TRBS);
                c.events = Consumer::new(EVENT_RING_TRBS);
                c.ep0 = Producer::new(TRANSFER_RING_TRBS);
                let ring = core::ptr::addr_of_mut!(COMMAND_RING);
                write_trb(ring, c.command.link_index(), link_trb(ring, false));
                let dcbaa = page(core::ptr::addr_of_mut!(DCBAA));
                if c.scratchpads != 0 {
                    unsafe {
                        core::ptr::write_volatile(
                            dcbaa as *mut u64,
                            page(core::ptr::addr_of_mut!(SCRATCHPAD_ARRAY)),
                        )
                    };
                    c.pool.install().map_err(|_| XhciError::Failed)?;
                }
                let events = page(core::ptr::addr_of_mut!(EVENT_RING));
                let erst = core::ptr::addr_of_mut!(ERST);
                unsafe {
                    core::ptr::write_volatile(word(erst, 0), events as u32);
                    core::ptr::write_volatile(word(erst, 4), (events >> 32) as u32);
                    core::ptr::write_volatile(word(erst, 8), EVENT_RING_TRBS as u32);
                }
                fence(Ordering::SeqCst);
                c.write32(c.operational(OP_CONFIG), u32::from(SLOTS_ENABLED));
                c.write64(c.operational(OP_DCBAAP), dcbaa);
                c.write64(c.operational(OP_CRCR), page(ring) | 1);
                c.write32(c.interrupter0(IR_IMAN), 1);
                c.write32(c.interrupter0(IR_IMOD), 0);
                c.write32(c.interrupter0(IR_ERSTSZ), 1);
                c.write64(c.interrupter0(IR_ERDP), events);
                c.write64(c.interrupter0(IR_ERSTBA), page(erst));
                self.advance(r, Step::Power(1));
            }
            Step::Power(port) => {
                let c = &mut r.controller;
                let value = c.read32(c.portsc(port));
                if r.watch_power
                    .initial_request(ticks(), port, value, c.layout.port_power_control)
                {
                    c.write32(
                        c.portsc(port),
                        rules::portsc_neutral(value) | rules::PORTSC_PP,
                    );
                }
                if port < c.layout.max_ports {
                    self.advance(r, Step::Power(port + 1));
                } else {
                    self.advance(r, Step::PowerWait);
                }
            }
            Step::PowerWait => {
                if r.expired() {
                    return Err(XhciError::Timeout("keyboard recovery power"));
                }
                if ticks().wrapping_sub(r.phase_tick) >= PORT_POWER_TICKS {
                    self.advance(r, Step::Route);
                }
            }
            Step::Route => {
                let c = &mut r.controller;
                if xhci_interrupt::STATE.snapshot() != self.retired {
                    return Err(XhciError::Keyboard(hid::Error::RetirementUncertain));
                }
                c.interrupt
                    .as_mut()
                    .unwrap()
                    .runtime_rearm(r.generation)
                    .map_err(XhciError::Interrupt)?;
                c.ownership_holds()?;
                c.interrupt
                    .as_mut()
                    .unwrap()
                    .enable(false)
                    .map_err(XhciError::Interrupt)?;
                c.ownership_holds()?;
                c.write32(c.operational(OP_USBSTS), USBSTS_EINT);
                c.write32(c.interrupter0(IR_IMAN), 3);
                if c.read32(c.interrupter0(IR_IMAN)) & 2 == 0 {
                    return Err(XhciError::Interrupt(xhci_irq::Error::Readback));
                }
                c.write32(c.operational(OP_USBCMD), USBCMD_RUN | USBCMD_INTE);
                self.advance(r, Step::RunWait);
            }
            Step::RunWait => {
                if !r.controller.halted() {
                    self.advance(r, Step::Scan(1));
                }
            }
            Step::Scan(port) => {
                let c = &mut r.controller;
                let value = c.read32(c.portsc(port));
                if !rules::port_power_ready(value, c.layout.port_power_control) {
                    r.watch_power.observe_unavailable(port);
                }
                // The condition may have cleared since Power. One fresh
                // attempt here covers that interval without a reset loop.
                if self.power_retry != Some(port)
                    && r.watch_power
                        .request(ticks(), port, value, c.layout.port_power_control)
                {
                    c.write32(
                        c.portsc(port),
                        rules::portsc_neutral(value) | rules::PORTSC_PP,
                    );
                    self.power_retry = Some(port);
                    self.advance(r, Step::PortPowerWait(port));
                    return Ok(());
                }
                self.ports[usize::from(port)] =
                    rules::port_observation(value, c.layout.port_power_control);
                let changes = value & rules::PORTSC_CHANGES;
                if changes != 0 {
                    c.write32(c.portsc(port), rules::portsc_neutral(value) | changes);
                }
                let connected = value & rules::PORTSC_CCS != 0;
                let refused = r.watch_power.blocked(port);
                let powered =
                    !refused && rules::port_power_ready(value, c.layout.port_power_control);
                if !powered {
                    let reason = if refused { "refused" } else { "port-power" };
                    let _ = writeln!(
                        serial::Serial,
                        "USB KEYBOARD UNSUPPORTED port={port} reason={reason} portsc={value:08x}"
                    );
                }
                self.speed = rules::port_speed(value);
                if powered
                    && connected
                    && matches!(
                        self.speed,
                        rules::SPEED_LOW | rules::SPEED_FULL | rules::SPEED_HIGH
                    )
                {
                    self.port = port;
                    if value & rules::PORTSC_PED == 0 {
                        c.write32(
                            c.portsc(port),
                            rules::portsc_neutral(value) | rules::PORTSC_PR,
                        );
                        self.advance(r, Step::PortWait);
                    } else {
                        self.command(
                            r,
                            [0, 0, 0, rules::control(rules::TRB_ENABLE_SLOT)],
                            Step::Enabled,
                        )?;
                    }
                } else if port < c.layout.max_ports {
                    self.advance(r, Step::Scan(port + 1));
                } else {
                    self.watching(r);
                }
            }
            Step::PortPowerWait(port) => {
                if r.expired() {
                    return Err(XhciError::Timeout("keyboard recovery port power"));
                }
                if ticks().wrapping_sub(r.phase_tick) >= PORT_POWER_TICKS {
                    self.advance(r, Step::Scan(port));
                }
            }
            Step::PortWait => {
                let c = &mut r.controller;
                let value = c.read32(c.portsc(self.port));
                if !rules::port_power_ready(value, c.layout.port_power_control) {
                    r.fence_power(self.port, "port power unavailable");
                    return Ok(());
                }
                if value & rules::PORTSC_PRC != 0 {
                    c.write32(
                        c.portsc(self.port),
                        rules::portsc_neutral(value) | rules::PORTSC_PRC,
                    );
                    if value & (rules::PORTSC_CCS | rules::PORTSC_PED)
                        != rules::PORTSC_CCS | rules::PORTSC_PED
                    {
                        return Err(XhciError::PortNotEnabled(value));
                    }
                    self.command(
                        r,
                        [0, 0, 0, rules::control(rules::TRB_ENABLE_SLOT)],
                        Step::Enabled,
                    )?;
                }
            }
            Step::Enabled => {
                r.slot = done.unwrap();
                if r.slot == 0 || r.slot > SLOTS_ENABLED {
                    return Err(XhciError::SlotId(r.slot));
                }
                self.packet = rules::initial_max_packet(self.speed)
                    .ok_or(XhciError::UnsupportedSpeed(self.speed))?;
                let c = &mut r.controller;
                let input = core::ptr::addr_of_mut!(INPUT_CONTEXT);
                let output = core::ptr::addr_of_mut!(DEVICE_CONTEXT);
                let ring = core::ptr::addr_of_mut!(EP0_RING);
                zero(input);
                zero(output);
                zero(ring);
                c.ep0 = Producer::new(TRANSFER_RING_TRBS);
                write_trb(ring, c.ep0.link_index(), link_trb(ring, false));
                let dequeue = page(ring) | 1;
                unsafe {
                    core::ptr::write_volatile(c.context(input, 0, 1), 3);
                    core::ptr::write_volatile(
                        c.context(input, 1, 0),
                        (1 << 27) | (u32::from(self.speed) << 20),
                    );
                    core::ptr::write_volatile(c.context(input, 1, 1), u32::from(self.port) << 16);
                    for (n, value) in [
                        0,
                        (u32::from(self.packet) << 16) | (4 << 3) | (3 << 1),
                        dequeue as u32,
                        (dequeue >> 32) as u32,
                        8,
                    ]
                    .iter()
                    .enumerate()
                    {
                        core::ptr::write_volatile(c.context(input, 2, n as u64), *value);
                    }
                    core::ptr::write_volatile(
                        (page(core::ptr::addr_of_mut!(DCBAA)) + 8 * u64::from(r.slot)) as *mut u64,
                        page(output),
                    );
                }
                self.context_command(r, rules::TRB_ADDRESS_DEVICE, Step::Addressed)?;
            }
            Step::Addressed => {
                let c = &mut r.controller;
                let state = unsafe {
                    core::ptr::read_volatile(c.context(
                        core::ptr::addr_of_mut!(DEVICE_CONTEXT),
                        0,
                        3,
                    ))
                };
                if state >> 27 != SLOT_STATE_ADDRESSED || state & 0xff == 0 {
                    return Err(XhciError::NotAddressed(state));
                }
                self.control(r, rules::get_descriptor_setup(1, 0, 8), 8, Step::Prefix)?;
            }
            Step::Prefix => {
                let bytes = self.bytes(8);
                let Ok(packet) = rules::max_packet0(&bytes[..8]) else {
                    return self.disable(r);
                };
                if packet != self.packet {
                    let c = &mut r.controller;
                    let input = core::ptr::addr_of_mut!(INPUT_CONTEXT);
                    zero(input);
                    unsafe {
                        core::ptr::write_volatile(c.context(input, 0, 1), 2);
                        core::ptr::write_volatile(
                            c.context(input, 2, 1),
                            (u32::from(packet) << 16) | (4 << 3) | (3 << 1),
                        );
                    }
                    self.context_command(r, rules::TRB_EVALUATE_CONTEXT, Step::Evaluated)?;
                } else {
                    self.device(r)?;
                }
            }
            Step::Evaluated => self.device(r)?,
            Step::Device => {
                if rules::device_descriptor(&self.bytes(18)[..18]).is_err() {
                    return self.disable(r);
                }
                self.control(r, rules::get_descriptor_setup(2, 0, 9), 9, Step::Header)?;
            }
            Step::Header => {
                let bytes = self.bytes(9);
                self.length = u16::from_le_bytes([bytes[2], bytes[3]]);
                if !(9..=hid::CONFIG_BYTES as u16).contains(&self.length) {
                    self.disable(r)?;
                } else {
                    self.control(
                        r,
                        rules::get_descriptor_setup(2, 0, self.length),
                        self.length,
                        Step::Configuration,
                    )?;
                }
            }
            Step::Configuration => {
                let bytes = self.bytes(usize::from(self.length));
                let Some(keyboard) =
                    hid::supported_configuration(&bytes[..usize::from(self.length)], self.speed)
                else {
                    return self.disable(r);
                };
                r.keyboard = Some(keyboard);
                r.port = self.port;
                let c = &mut r.controller;
                let input = core::ptr::addr_of_mut!(INPUT_CONTEXT);
                let ring = core::ptr::addr_of_mut!(KEYBOARD_RING);
                zero(input);
                zero(ring);
                zero(core::ptr::addr_of_mut!(KEYBOARD_REPORT));
                write_trb(ring, TRANSFER_RING_TRBS - 1, link_trb(ring, false));
                let dci = keyboard.endpoint.dci();
                unsafe {
                    core::ptr::write_volatile(c.context(input, 0, 1), 1 | (1 << dci));
                    core::ptr::write_volatile(
                        c.context(input, 1, 0),
                        (u32::from(dci) << 27) | (u32::from(self.speed) << 20),
                    );
                    core::ptr::write_volatile(c.context(input, 1, 1), u32::from(self.port) << 16);
                    for (n, value) in keyboard.endpoint.context(page(ring)).iter().enumerate() {
                        core::ptr::write_volatile(
                            c.context(input, u64::from(dci) + 1, n as u64),
                            *value,
                        );
                    }
                }
                self.context_command(r, rules::TRB_CONFIGURE_ENDPOINT, Step::Configured)?;
            }
            Step::Configured => self.control(
                r,
                hid::setup(0, 9, u16::from(r.keyboard.unwrap().configuration), 0, 0),
                0,
                Step::SetConfiguration,
            )?,
            Step::SetConfiguration => self.control(
                r,
                hid::setup(0x21, 0x0b, 0, u16::from(r.keyboard.unwrap().interface), 0),
                0,
                Step::SetProtocol,
            )?,
            Step::SetProtocol => self.control(
                r,
                hid::setup(0xa1, 3, 0, u16::from(r.keyboard.unwrap().interface), 1),
                1,
                Step::GetProtocol,
            )?,
            Step::GetProtocol => {
                if self.bytes(1)[0] != 0 {
                    return Err(XhciError::Keyboard(hid::Error::Hid));
                }
                self.control(
                    r,
                    hid::setup(0x21, 0x0a, 0, u16::from(r.keyboard.unwrap().interface), 0),
                    0,
                    Step::SetIdle,
                )?;
            }
            Step::SetIdle => {
                r.set_phase(Phase::Running);
                r.post()?;
                if r.phase == Phase::Running {
                    if let Some(port) = r.watch_power.bound(r.port) {
                        power_refused(port);
                    }
                    let _ = writeln!(
                        serial::Serial,
                        "USB KEYBOARD REBOUND generation={} port={} slot={}",
                        r.generation,
                        r.port,
                        r.slot
                    );
                }
            }
            Step::Disabled => {
                let entry = page(core::ptr::addr_of_mut!(DCBAA)) + 8 * u64::from(r.slot);
                unsafe { core::ptr::write_volatile(entry as *mut u64, 0) };
                let _ = writeln!(
                    serial::Serial,
                    "USB KEYBOARD UNSUPPORTED port={}",
                    self.port
                );
                r.slot = 0;
                if self.port < r.controller.layout.max_ports {
                    self.advance(r, Step::Scan(self.port + 1));
                } else {
                    self.watching(r);
                }
            }
            Step::Watch(port) => {
                let c = &mut r.controller;
                xhci_interrupt::STATE
                    .check()
                    .map_err(XhciError::Interrupt)?;
                if c.status()
                    & (USBSTS_HOST_SYSTEM_ERROR | USBSTS_HOST_CONTROLLER_ERROR | USBSTS_HALTED)
                    != 0
                {
                    return Err(XhciError::Failed);
                }
                let value = c.read32(c.portsc(port));
                if !rules::port_power_ready(value, c.layout.port_power_control) {
                    r.watch_power.observe_unavailable(port);
                }
                if !r.watch_power.blocked(port)
                    && rules::port_watch_changed(
                        self.ports[usize::from(port)],
                        value,
                        c.layout.port_power_control,
                    )
                {
                    let restored = rules::port_watch_restored(
                        self.ports[usize::from(port)],
                        value,
                        c.layout.port_power_control,
                    );
                    if !restored || r.watch_power.reconstruct(port) {
                        r.fence_input("port changed");
                        return Ok(());
                    }
                }
                self.ports[usize::from(port)] =
                    rules::port_observation(value, c.layout.port_power_control);
                let changes = value & rules::PORTSC_CHANGES;
                if r.watch_power
                    .request(ticks(), port, value, c.layout.port_power_control)
                {
                    c.write32(
                        c.portsc(port),
                        rules::portsc_neutral(value) | changes | rules::PORTSC_PP,
                    );
                    self.advance(r, Step::WatchPowerWait(port));
                    return Ok(());
                }
                if changes != 0 {
                    c.write32(c.portsc(port), rules::portsc_neutral(value) | changes);
                }
                // Acknowledge at most eight accumulated port changes per pass.
                for _ in 0..PUMP_EVENTS {
                    let Some(event) = c.take_event()? else { break };
                    if let Event::PortStatusChange { port } = event {
                        if port == 0 || port > c.layout.max_ports {
                            return Err(XhciError::Unexpected(event));
                        }
                        let value = c.read32(c.portsc(port));
                        if !rules::port_power_ready(value, c.layout.port_power_control) {
                            r.watch_power.observe_unavailable(port);
                        }
                        if !r.watch_power.blocked(port)
                            && rules::port_watch_changed(
                                self.ports[usize::from(port)],
                                value,
                                c.layout.port_power_control,
                            )
                        {
                            let restored = rules::port_watch_restored(
                                self.ports[usize::from(port)],
                                value,
                                c.layout.port_power_control,
                            );
                            if !restored || r.watch_power.reconstruct(port) {
                                r.fence_input("port changed");
                                return Ok(());
                            }
                        }
                        self.ports[usize::from(port)] =
                            rules::port_observation(value, c.layout.port_power_control);
                        c.write32(
                            c.portsc(port),
                            rules::portsc_neutral(value) | (value & rules::PORTSC_CHANGES),
                        );
                    } else {
                        return Err(XhciError::Unexpected(event));
                    }
                }
                self.step = Step::Watch(if port < c.layout.max_ports {
                    port + 1
                } else {
                    1
                });
            }
            Step::WatchPowerWait(port) => {
                // Let PP settle before interpreting a momentary readback as
                // restoration. Like Watch, this requires advancing PIT ticks.
                if ticks().wrapping_sub(r.phase_tick) >= PORT_POWER_TICKS {
                    self.advance(r, Step::Watch(port));
                }
            }
        }
        Ok(())
    }
}
