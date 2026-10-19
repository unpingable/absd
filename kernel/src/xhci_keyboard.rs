//! One long-lived root-port boot keyboard. A child of xhci so its controller
//! ownership and static DMA implementation remain private to that driver.

use super::*;
use absd_kernel::usb_keyboard::{self as hid, Keyboard, Reports};

#[path = "xhci_keyboard_recovery.rs"]
mod recovery;

const PUMP_EVENTS: usize = 8;
const STOP_TSC: u64 = 1 << 34;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Running,
    Fenced,
    Halting,
    Draining,
    Clean,
    Quarantined,
    Recovering,
    Watching,
}

struct Runtime {
    controller: Controller,
    keyboard: Option<Keyboard>,
    port: u8,
    slot: u8,
    ring: Producer,
    outstanding: Option<u64>,
    reports: Reports,
    phase: Phase,
    last_tick: Option<u64>,
    phase_tick: u64,
    phase_tsc: u64,
    irq_baseline: u64,
    generation: u64,
    uncredited: Option<u64>,
    quiet: Option<(u64, xhci_irq::Snapshot)>,
    cleanable: bool,
    observe: bool,
    accepted_reports: u64,
    max_events: usize,
    test_race: bool,
    race_deadline: Option<u64>,
    race_done: bool,
    last_report_tick: u64,
    idle_reported: bool,
    recover: bool,
    shutdown: bool,
    successors: u8,
    watch_power: rules::PortPowerRetry,
    recovery: Option<recovery::Recovery>,
    recovery_test: KeyboardRecoveryTest,
}

// BSP-only, IF clear. No reference escapes a pump call or enters the ISR.
static mut RUNTIME: Option<Runtime> = None;

impl Controller {
    fn keyboard_control_none(&mut self, slot: u8, setup: u64) -> Result<(), XhciError> {
        let (first, control) = self.push_ep0(
            [
                setup as u32,
                (setup >> 32) as u32,
                8,
                rules::control(rules::TRB_SETUP) | rules::TRB_IDT,
            ],
            true,
        );
        let (last, _) = self.push_ep0(
            [
                0,
                0,
                0,
                rules::control(rules::TRB_STATUS) | rules::DIRECTION_IN | rules::TRB_IOC,
            ],
            false,
        );
        self.ownership_holds()?;
        fence(Ordering::SeqCst);
        unsafe { core::ptr::write_volatile((first + 12) as *mut u32, control) };
        self.doorbell(slot, u32::from(EP0));
        let (code, _) = self.wait_event(
            Wait::Transfer {
                first,
                data: first,
                last,
                slot,
                endpoint: EP0,
            },
            TRANSFER_TICKS,
            "keyboard control",
        )?;
        if code != rules::COMPLETION_SUCCESS {
            return self.fail(XhciError::Transfer { code });
        }
        Ok(())
    }

    fn keyboard_configuration(
        &mut self,
        slot: u8,
        speed: u8,
    ) -> Result<Option<Keyboard>, XhciError> {
        self.ownership_holds()?;
        self.control_in(slot, rules::get_descriptor_setup(2, 0, 9), 9)?;
        let data = page(core::ptr::addr_of_mut!(DATA)) as *const u8;
        let length = unsafe {
            u16::from_le_bytes([
                core::ptr::read_volatile(data.add(2)),
                core::ptr::read_volatile(data.add(3)),
            ])
        };
        if !(9..=hid::CONFIG_BYTES as u16).contains(&length) {
            return Ok(None);
        }
        self.ownership_holds()?;
        self.control_in(slot, rules::get_descriptor_setup(2, 0, length), length)?;
        let mut bytes = [0; hid::CONFIG_BYTES];
        for (n, byte) in bytes[..usize::from(length)].iter_mut().enumerate() {
            *byte = unsafe { core::ptr::read_volatile(data.add(n)) };
        }
        // A complete but unsupported configuration rejects this device only.
        // Control/ownership errors above remain fatal; the caller confirms
        // Disable Slot before reusing any enumeration storage on another port.
        Ok(hid::supported_configuration(
            &bytes[..usize::from(length)],
            speed,
        ))
    }

    fn keyboard_configure(
        &mut self,
        slot: u8,
        port: u8,
        speed: u8,
        keyboard: Keyboard,
    ) -> Result<(), XhciError> {
        let input = core::ptr::addr_of_mut!(INPUT_CONTEXT);
        let ring = core::ptr::addr_of_mut!(KEYBOARD_RING);
        zero(input);
        zero(ring);
        zero(core::ptr::addr_of_mut!(KEYBOARD_REPORT));
        let dci = keyboard.endpoint.dci();
        write_trb(ring, TRANSFER_RING_TRBS - 1, link_trb(ring, false));
        unsafe {
            core::ptr::write_volatile(self.context(input, 0, 1), 1 | (1 << dci));
            // Reconstruct the slot's known root-port/non-hub attributes;
            // never copy the output-only address/state bits as input ABI.
            core::ptr::write_volatile(
                self.context(input, 1, 0),
                (u32::from(dci) << 27) | (u32::from(speed) << 20),
            );
            core::ptr::write_volatile(self.context(input, 1, 1), u32::from(port) << 16);
            for (n, value) in keyboard.endpoint.context(page(ring)).iter().enumerate() {
                core::ptr::write_volatile(
                    self.context(input, u64::from(dci) + 1, n as u64),
                    *value,
                );
            }
        }
        self.ownership_holds()?;
        self.command(
            [
                page(input) as u32,
                (page(input) >> 32) as u32,
                0,
                rules::control(rules::TRB_CONFIGURE_ENDPOINT) | (u32::from(slot) << 24),
            ],
            true,
        )?;
        self.keyboard_control_none(
            slot,
            hid::setup(0, 9, u16::from(keyboard.configuration), 0, 0),
        )?;
        self.keyboard_control_none(
            slot,
            hid::setup(0x21, 0x0b, 0, u16::from(keyboard.interface), 0),
        )?;
        self.ownership_holds()?;
        self.control_in(
            slot,
            hid::setup(0xa1, 3, 0, u16::from(keyboard.interface), 1),
            1,
        )?;
        if unsafe { core::ptr::read_volatile(page(core::ptr::addr_of_mut!(DATA)) as *const u8) }
            != 0
        {
            return Err(XhciError::Keyboard(hid::Error::Hid));
        }
        self.keyboard_control_none(
            slot,
            hid::setup(0x21, 0x0a, 0, u16::from(keyboard.interface), 0),
        )?;
        self.drain()?;
        serial::write("USB KEYBOARD ENDPOINT slot=");
        serial::decimal(u64::from(slot));
        serial::write(" port=");
        serial::decimal(u64::from(port));
        serial::write(" dci=");
        serial::decimal(u64::from(dci));
        serial::write(" packet=");
        serial::decimal(u64::from(keyboard.endpoint.packet));
        serial::write(" interval=");
        serial::decimal(u64::from(keyboard.endpoint.interval));
        serial::write(" ring=");
        serial::hex(page(ring));
        serial::write(" context=");
        serial::hex(
            page(core::ptr::addr_of_mut!(DEVICE_CONTEXT))
                + self.layout.context_bytes * u64::from(dci),
        );
        serial::write(" report=");
        serial::hex(page(core::ptr::addr_of_mut!(KEYBOARD_REPORT)));
        serial::write("\n");
        Ok(())
    }
}

impl Runtime {
    fn set_phase(&mut self, phase: Phase) {
        self.phase = phase;
        self.phase_tick = ticks();
        self.phase_tsc = unsafe { core::arch::x86_64::_rdtsc() };
        let _ = writeln!(serial::Serial, "USB KEYBOARD STATE {phase:?}");
    }

    fn fence_input(&mut self, reason: &str) {
        if !matches!(
            self.phase,
            Phase::Running | Phase::Recovering | Phase::Watching
        ) {
            return;
        }
        serial::write("USB KEYBOARD FENCED reason=");
        serial::write(reason);
        serial::write("\n");
        self.reports.fence();
        self.set_phase(Phase::Fenced);
    }

    fn fence_power(&mut self, port: u8, reason: &str) {
        if !matches!(
            self.phase,
            Phase::Running | Phase::Recovering | Phase::Watching
        ) {
            return;
        }
        self.watch_power.advance(ticks());
        if let Some(port) = self.watch_power.unavailable(port) {
            recovery::power_refused(port);
        }
        self.fence_input(reason);
    }

    fn quarantine(&mut self) {
        // No register/configuration access: ownership may already be lost.
        xhci_interrupt::STATE.retire();
        self.reports.fence();
        self.set_phase(Phase::Quarantined);
        serial::write("USB KEYBOARD QUARANTINED statics=reserved\n");
    }

    fn expired(&self) -> bool {
        ticks().wrapping_sub(self.phase_tick) > HALT_TICKS
            || unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(self.phase_tsc) > STOP_TSC
    }

    fn post(&mut self) -> Result<(), XhciError> {
        assert_eq!(self.phase, Phase::Running);
        assert!(self.outstanding.is_none());
        let keyboard = self.keyboard.unwrap();
        let c = &mut self.controller;
        c.ownership_holds()?;
        let port = c.read32(c.portsc(self.port));
        if !rules::port_power_ready(port, c.layout.port_power_control) {
            self.fence_power(self.port, "port power unavailable");
            return Ok(());
        }
        if port & (rules::PORTSC_CCS | rules::PORTSC_PED) != rules::PORTSC_CCS | rules::PORTSC_PED {
            self.fence_input("disconnected");
            return Ok(());
        }
        let ring = core::ptr::addr_of_mut!(KEYBOARD_RING);
        let claim = self.ring.claim();
        let data = page(core::ptr::addr_of_mut!(KEYBOARD_REPORT));
        zero(core::ptr::addr_of_mut!(KEYBOARD_REPORT));
        write_trb(
            ring,
            claim.index,
            [
                data as u32,
                (data >> 32) as u32,
                hid::REPORT_BYTES as u32,
                with_cycle(
                    rules::control(rules::TRB_NORMAL) | rules::TRB_IOC | rules::TRB_ISP,
                    claim.cycle,
                ),
            ],
        );
        if let Some(cycle) = claim.link {
            write_trb(ring, self.ring.link_index(), link_trb(ring, cycle));
        }
        c.ownership_holds()?;
        self.outstanding = Some(page(ring) + claim.index as u64 * rules::TRB_BYTES);
        self.irq_baseline = xhci_interrupt::STATE.credit_baseline();
        self.uncredited = None;
        c.doorbell(self.slot, u32::from(keyboard.endpoint.dci()));
        Ok(())
    }

    fn running(&mut self) -> Result<(), XhciError> {
        self.controller.ownership_holds()?;
        let port = self.controller.read32(self.controller.portsc(self.port));
        if !rules::port_power_ready(port, self.controller.layout.port_power_control) {
            self.fence_power(self.port, "port power unavailable");
            return Ok(());
        }
        if port & (rules::PORTSC_CCS | rules::PORTSC_PED) != rules::PORTSC_CCS | rules::PORTSC_PED {
            self.fence_input("disconnected");
            return Ok(());
        }
        let status = self.controller.status();
        if status & (USBSTS_HOST_SYSTEM_ERROR | USBSTS_HOST_CONTROLLER_ERROR | USBSTS_HALTED) != 0 {
            return Err(XhciError::ControllerError(status));
        }
        xhci_interrupt::STATE
            .check()
            .map_err(XhciError::Interrupt)?;
        if xhci_interrupt::STATE.snapshot().generation != self.generation {
            return Err(XhciError::Interrupt(xhci_irq::Error::Drain));
        }
        if self.observe
            && !self.idle_reported
            && self.outstanding.is_some()
            && !self.controller.event_available()
            && ticks().wrapping_sub(self.last_report_tick) >= 250
        {
            serial::write("USB KEYBOARD IDLE ticks=");
            serial::decimal(ticks().wrapping_sub(self.last_report_tick));
            serial::write(" outstanding=1 acknowledged=");
            serial::decimal(self.controller.events_seen);
            serial::write("\n");
            self.idle_reported = true;
        }
        if self.test_race && !self.race_done && self.controller.event_available() {
            if self.race_deadline.is_none() {
                self.race_deadline = crate::syscalls::usb_keyboard_test_deadline();
                if let Some(deadline) = self.race_deadline {
                    serial::write("USB KEYBOARD TEST RACE HELD deadline=");
                    serial::decimal(deadline);
                    serial::write("\n");
                }
            }
            if let Some(deadline) = self.race_deadline {
                if ticks() < deadline {
                    return Ok(());
                }
                self.race_done = true;
                serial::write("USB KEYBOARD TEST RACE RELEASED tick=");
                serial::decimal(ticks());
                serial::write("\n");
            }
        }
        if self.controller.event_available()
            && xhci_interrupt::STATE.snapshot().count == self.irq_baseline
        {
            let start = *self.uncredited.get_or_insert_with(ticks);
            if ticks().wrapping_sub(start) > IRQ_WAIT_TICKS {
                return Err(XhciError::Interrupt(
                    xhci_irq::Error::CompletedWithoutInterrupt,
                ));
            }
            return Ok(());
        }
        let mut consumed = 0;
        for _ in 0..PUMP_EVENTS {
            self.controller.ownership_holds()?;
            let Some(event) = self.controller.take_event()? else {
                break;
            };
            consumed += 1;
            match event {
                Event::PortStatusChange { port }
                    if port != 0 && port <= self.controller.layout.max_ports =>
                {
                    let at = self.controller.portsc(port);
                    let value = self.controller.read32(at);
                    self.controller.write32(
                        at,
                        rules::portsc_neutral(value) | (value & rules::PORTSC_CHANGES),
                    );
                    if port == self.port
                        && !rules::port_power_ready(
                            value,
                            self.controller.layout.port_power_control,
                        )
                    {
                        self.fence_power(port, "port power unavailable");
                        break;
                    }
                    if port == self.port && value & rules::PORTSC_CCS == 0 {
                        self.fence_input("disconnected");
                        break;
                    }
                }
                transfer @ Event::Transfer { .. } => {
                    hid::completion(
                        transfer,
                        self.outstanding
                            .ok_or(XhciError::Keyboard(hid::Error::CompletionIdentity))?,
                        self.slot,
                        self.keyboard.unwrap().endpoint.dci(),
                    )
                    .map_err(XhciError::Keyboard)?;
                    self.outstanding = None;
                    self.last_report_tick = ticks();
                    self.idle_reported = false;
                    self.controller.ownership_holds()?;
                    let value = self.controller.read32(self.controller.portsc(self.port));
                    if !rules::port_power_ready(value, self.controller.layout.port_power_control) {
                        self.fence_power(self.port, "port power unavailable");
                        break;
                    }
                    if value & (rules::PORTSC_CCS | rules::PORTSC_PED)
                        != rules::PORTSC_CCS | rules::PORTSC_PED
                    {
                        self.fence_input("disconnected");
                        break;
                    }
                    let mut bytes = [0; hid::REPORT_BYTES];
                    fence(Ordering::SeqCst);
                    let data = page(core::ptr::addr_of_mut!(KEYBOARD_REPORT)) as *const u8;
                    for (n, byte) in bytes.iter_mut().enumerate() {
                        *byte = unsafe { core::ptr::read_volatile(data.add(n)) };
                    }
                    if let Ok(presses) = self.reports.translate(&bytes) {
                        let accepted = serial::keyboard_input(presses.bytes());
                        self.accepted_reports = self.accepted_reports.saturating_add(1);
                        if self.observe && accepted != 0 {
                            serial::write("USB KEYBOARD ENQUEUED bytes=");
                            serial::decimal(accepted as u64);
                            let (total, dropped) =
                                serial::input_counts(absd_kernel::console_input::Source::Keyboard);
                            serial::write(" total=");
                            serial::decimal(total);
                            serial::write(" dropped=");
                            serial::decimal(dropped);
                            serial::write("\n");
                        }
                    }
                }
                other => return Err(XhciError::Unexpected(other)),
            }
        }
        self.max_events = self.max_events.max(consumed);
        if self.observe && consumed != 0 {
            serial::write("USB KEYBOARD PROGRESS tick=");
            serial::decimal(ticks());
            serial::write(" events=");
            serial::decimal(consumed as u64);
            serial::write(" acknowledged=");
            serial::decimal(self.controller.events_seen);
            serial::write("\n");
        }
        if self.phase == Phase::Running && self.outstanding.is_none() {
            self.post()?;
        }
        Ok(())
    }

    fn stop_step(&mut self) -> Result<(), XhciError> {
        let expired = self.expired();
        let c = &mut self.controller;
        match self.phase {
            Phase::Fenced => {
                c.ownership_holds()?;
                let substitute = self.shutdown
                    && self.successors == 1
                    && self.recovery_test == KeyboardRecoveryTest::ResetTimeout;
                if substitute {
                    serial::write(
                        "USB KEYBOARD RECOVERY STOP RESET WAIT source=observation-substitution\n",
                    );
                    self.recovery_test = KeyboardRecoveryTest::None;
                }
                // A process-suite stop may arrive during asynchronous HCRST.
                // Wait across ticks for reset to finish before requesting halt.
                if c.read32(c.operational(OP_USBCMD)) & USBCMD_RESET != 0
                    || c.status() & USBSTS_NOT_READY != 0
                    || substitute
                {
                    if expired {
                        self.quarantine();
                    }
                    return Ok(());
                }
                c.write32(c.interrupter0(IR_IMAN), 1);
                self.cleanable &= c.read32(c.interrupter0(IR_IMAN)) & 2 == 0;
                let command = c.read32(c.operational(OP_USBCMD));
                c.write32(c.operational(OP_USBCMD), command & !USBCMD_INTE);
                self.cleanable &= c.read32(c.operational(OP_USBCMD)) & USBCMD_INTE == 0;
                c.ownership_holds()?;
                self.cleanable &= c.interrupt.as_mut().unwrap().disable().is_ok();
                c.ownership_holds()?;
                c.write32(
                    c.operational(OP_USBCMD),
                    command & !(USBCMD_INTE | USBCMD_RUN),
                );
                self.set_phase(Phase::Halting);
            }
            Phase::Halting => {
                c.ownership_holds()?;
                let halted = c.halted();
                if !halted && !expired {
                    return Ok(());
                }
                c.ownership_holds()?;
                c.bus_master_off();
                let dma_off = !pci::bus_master(c.function);
                let _ = c.status();
                if !halted || !dma_off || !self.cleanable {
                    self.quarantine();
                    return Ok(());
                }
                serial::write("USB KEYBOARD HALTED DMA_OFF bus_master=0\n");
                self.set_phase(Phase::Draining);
            }
            Phase::Draining => {
                let seen = xhci_interrupt::STATE.snapshot();
                let pending = c.interrupt.as_ref().unwrap().pending();
                if expired {
                    self.quarantine();
                    return Ok(());
                }
                if pending || self.quiet.is_some_and(|(_, before)| before != seen) {
                    self.quiet = None;
                }
                if !pending {
                    let (start, _) = *self.quiet.get_or_insert((ticks(), seen));
                    if ticks().wrapping_sub(start) >= 20 {
                        self.set_phase(Phase::Clean);
                        serial::write("USB KEYBOARD QUIET late=");
                        serial::decimal(seen.late);
                        serial::write(" max_events=");
                        serial::decimal(self.max_events as u64);
                        serial::write(" reports=");
                        serial::decimal(self.accepted_reports);
                        serial::write("\n");
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

pub(super) fn initialize(
    observe: bool,
    masked: bool,
    test_race: bool,
    recover: bool,
    recovery_test: KeyboardRecoveryTest,
) {
    crate::debug_assert_interrupts_disabled();
    assert!(!crate::kernel_lock::active());
    assert!(unsafe { (*core::ptr::addr_of!(RUNTIME)).is_none() });
    let plan = Plan {
        interrupts: true,
        rounds: 1,
        fault: if masked {
            Fault::MaskedVector
        } else {
            Fault::None
        },
        hotplug: false,
        firmware: None,
        scratchpads: None,
        pagesize: None,
        observe: false,
    };
    let mut c = match probe(plan) {
        Ok(c) => c,
        Err(failure) => {
            report("USB KEYBOARD REFUSED ", failure.error);
            serial::write("USB KEYBOARD STATE Refused\n");
            if let Some(function) = failure.function {
                match failure.custody {
                    Custody::Released => report_dma(function),
                    Custody::Abandoned => report_abandoned(function, failure.usbcmd),
                    Custody::Preserved(owner) => {
                        if failure.restore_decode {
                            pci::disable_memory_decode(function);
                            serial::write("XHCI MEMORY DECODE RESTORED off\n");
                        }
                        report_preserved(function, owner, failure.usbcmd, failure.legacy);
                    }
                }
            }
            return;
        }
    };
    let recover = if recover && !c.interrupt.as_ref().unwrap().runtime_capable() {
        serial::write("USB KEYBOARD RECOVERY REFUSED reason=msix-vector-count stop_only=1\n");
        false
    } else {
        recover
    };
    c.round = 1;
    let selection = (|| -> Result<Option<(u8, u8, Keyboard)>, XhciError> {
        c.start_with_port_policy(plan.fault, true)?;
        for port in 1..=c.layout.max_ports {
            c.drain()?;
            let value = c.read32(c.portsc(port));
            if !rules::port_power_ready(value, c.layout.port_power_control) {
                let _ = writeln!(
                    serial::Serial,
                    "USB KEYBOARD UNSUPPORTED port={port} reason=port-power portsc={value:08x}"
                );
                continue;
            }
            let speed = rules::port_speed(value);
            if value & rules::PORTSC_CCS == 0
                || !matches!(
                    speed,
                    rules::SPEED_LOW | rules::SPEED_FULL | rules::SPEED_HIGH
                )
            {
                continue;
            }
            let (slot, _, _) = c.enumerate(port)?;
            if let Some(keyboard) = c.keyboard_configuration(slot, speed)? {
                c.keyboard_configure(slot, port, speed, keyboard)?;
                return Ok(Some((port, slot, keyboard)));
            }
            serial::write("USB KEYBOARD UNSUPPORTED port=");
            serial::decimal(u64::from(port));
            serial::write("\n");
            c.ownership_holds()?;
            c.disable_slot(slot)?;
        }
        Ok(None)
    })();
    let chosen = match selection {
        Ok(value) => value,
        Err(error) => {
            report("USB KEYBOARD INITIALIZATION FAILED ", error);
            None
        }
    };
    let (port, slot, keyboard) = chosen.map_or((0, 0, None), |(p, s, k)| (p, s, Some(k)));
    let mut runtime = Runtime {
        controller: c,
        keyboard,
        port,
        slot,
        ring: Producer::new(TRANSFER_RING_TRBS),
        outstanding: None,
        reports: Reports::new(),
        phase: if chosen.is_some() {
            Phase::Running
        } else {
            Phase::Fenced
        },
        last_tick: None,
        phase_tick: ticks(),
        phase_tsc: unsafe { core::arch::x86_64::_rdtsc() },
        irq_baseline: xhci_interrupt::STATE.credit_baseline(),
        generation: xhci_interrupt::STATE.snapshot().generation,
        uncredited: None,
        quiet: None,
        cleanable: true,
        observe,
        accepted_reports: 0,
        max_events: 0,
        test_race,
        race_deadline: None,
        race_done: false,
        last_report_tick: ticks(),
        idle_reported: false,
        recover,
        shutdown: false,
        successors: 0,
        watch_power: rules::PortPowerRetry::new(ticks()),
        recovery: None,
        recovery_test,
    };
    if runtime.phase == Phase::Running {
        if let Err(error) = runtime.post() {
            report("USB KEYBOARD INITIALIZATION FAILED ", error);
            runtime.fence_input("initial post");
        } else {
            serial::write("USB KEYBOARD READY\n");
        }
    } else {
        serial::write("USB KEYBOARD UNAVAILABLE serial_fallback=1\n");
    }
    unsafe { *core::ptr::addr_of_mut!(RUNTIME) = Some(runtime) };
}

pub(super) fn progress() {
    crate::debug_assert_interrupts_disabled();
    crate::kernel_lock::assert_bsp_device_access();
    let storage = unsafe { &mut *core::ptr::addr_of_mut!(RUNTIME) };
    if let Some(r) = storage.as_mut()
        && r.phase == Phase::Clean
        && r.recover
        && !r.shutdown
        && r.successors == recovery::MAX_SUCCESSORS
    {
        serial::write("USB KEYBOARD RECOVERY REFUSED budget=32 statics=reserved\n");
        r.recover = false;
    }
    if storage.as_ref().is_some_and(|r| {
        r.phase == Phase::Clean
            && r.recover
            && !r.shutdown
            && r.successors < recovery::MAX_SUCCESSORS
    }) {
        // Supervisor constructs a successor from a terminal generation. The
        // old report translator and outstanding TD never become live again.
        *storage = Some(recovery::successor(storage.take().unwrap()));
    }
    let Some(runtime) = storage.as_mut() else {
        return;
    };
    assert!(crate::kernel_lock::active());
    crate::kernel_lock::assert_held(crate::kernel_lock::BSP);
    if matches!(runtime.phase, Phase::Clean | Phase::Quarantined) {
        return;
    }
    let now = ticks();
    if runtime.last_tick == Some(now) {
        return;
    }
    runtime.last_tick = Some(now);
    runtime.watch_power.advance(now);
    // One pass per tick, <=8 events with fixed register operations, or one
    // stop phase. No port scan or blocking command occurs in this path.
    let result = match runtime.phase {
        Phase::Running => runtime.running(),
        Phase::Recovering | Phase::Watching => {
            let mut recovery = runtime.recovery.take().unwrap();
            let before = runtime.controller.events_seen;
            let result = recovery.progress(runtime);
            let events = runtime.controller.events_seen - before;
            assert!(events <= PUMP_EVENTS as u64);
            if runtime.observe && events != 0 {
                let _ = writeln!(
                    serial::Serial,
                    "USB KEYBOARD RECOVERY PROGRESS tick={} events={events} acknowledged={}",
                    ticks(),
                    runtime.controller.events_seen
                );
            }
            if matches!(runtime.phase, Phase::Recovering | Phase::Watching) {
                runtime.recovery = Some(recovery);
            }
            result
        }
        _ => runtime.stop_step(),
    };
    if let Err(error) = result {
        report("USB KEYBOARD FAILED ", error);
        if matches!(
            error,
            XhciError::OwnershipLost(_)
                | XhciError::Keyboard(hid::Error::RetirementUncertain | hid::Error::ResetTimeout)
                | XhciError::Interrupt(
                    xhci_irq::Error::Drain
                        | xhci_irq::Error::Readback
                        | xhci_irq::Error::Interrupters { .. }
                )
                | XhciError::Refused(_)
                | XhciError::UnsupportedSpeed(_)
        ) || !matches!(
            runtime.phase,
            Phase::Running | Phase::Recovering | Phase::Watching
        ) {
            runtime.quarantine();
        } else {
            // Descriptor failures precede assignment of the bound port.
            // Watching has no current candidate to charge for a power loss.
            let port = match runtime.phase {
                Phase::Running => runtime.port,
                Phase::Recovering => runtime
                    .recovery
                    .as_ref()
                    .map_or(0, |recovery| recovery.current_port()),
                _ => 0,
            };
            if port != 0
                && port <= runtime.controller.layout.max_ports
                && runtime.controller.ownership_holds().is_ok()
                && !rules::port_power_ready(
                    runtime.controller.read32(runtime.controller.portsc(port)),
                    runtime.controller.layout.port_power_control,
                )
            {
                runtime.fence_power(port, "port power unavailable");
            } else {
                runtime.fence_input("runtime fault");
            }
        }
    }
}

pub(super) fn stop_before_finish() -> bool {
    let Some(runtime) = (unsafe { &mut *core::ptr::addr_of_mut!(RUNTIME) }).as_mut() else {
        return false;
    };
    runtime.shutdown = true;
    if runtime.phase == Phase::Recovering
        && let Some(recovery) = runtime.recovery.as_ref()
    {
        recovery.report_stop(runtime.generation);
    }
    if matches!(
        runtime.phase,
        Phase::Running | Phase::Recovering | Phase::Watching
    ) {
        runtime.fence_input("processes finished");
    }
    matches!(
        runtime.phase,
        Phase::Fenced | Phase::Halting | Phase::Draining | Phase::Recovering
    )
}
