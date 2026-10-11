#!/usr/bin/env python3
"""Bounded single-task model for CPU ownership, queue transfer and stop drain.

This is a test-only protocol sketch.  It models the current global-BKL
serialization boundary; it does not model interrupts, memory ordering, APICs,
address translation, or a general scheduler.
"""
from dataclasses import dataclass, replace


class ProtocolError(AssertionError):
    pass


@dataclass(frozen=True)
class Task:
    online: int
    slot: int = 3
    pid: int = 41
    generation: int = 7
    owner: int | None = 0       # scheduler CpuClaim owner
    hardware: int | None = 0    # still executing/using stack, CR3, TSS, handlers
    last_cpu: int = 0
    epoch: int = 1
    departed_epoch: int = 0
    saved: bool = False
    queue: frozenset[int] = frozenset()
    stop: str = "active"        # active/requested/observed/departed/acked/reclaimed
    ack: tuple | None = None     # exact (slot,pid,generation,cpu,epoch)
    resources: bool = True
    handlers: bool = True

    @property
    def state(self):
        if self.stop == "reclaimed":
            return "Reclaimed"
        if self.stop in ("requested", "observed"):
            return "Stopping"
        if self.hardware is not None:
            return f"Running{chr(ord('A') + self.hardware)}"
        if self.stop in ("departed", "acked"):
            return f"Departed{chr(ord('A') + self.last_cpu)}"
        if self.queue:
            cpu = next(iter(self.queue))
            label = "Transferred" if cpu != 0 else "Queued"
            return f"{label}{chr(ord('A') + cpu)}"
        return "Unowned"

    @property
    def owner_or_last_cpu(self):
        if self.owner is not None:
            return self.owner
        return self.last_cpu

    def check(self):
        assert 2 <= self.online <= 6
        assert self.hardware is None or 0 <= self.hardware < self.online
        assert self.owner is None or 0 <= self.owner < self.online
        assert len(self.queue) <= 1, "duplicate stolen queue owner"
        assert all(0 <= cpu < self.online for cpu in self.queue)
        assert not (self.hardware is not None and self.queue), "running task also queued"
        assert (self.hardware is None) == (self.owner is None), "software/hardware owner mismatch"
        if self.hardware is not None:
            assert self.owner == self.hardware
            assert self.stop not in ("departed", "acked", "reclaimed")
        if self.queue:
            assert self.saved, "context was not saved before queue publication"
            assert self.departed_epoch == self.epoch, "queue published before departure"
            assert self.stop == "active", "stopped task was queued"
        if self.stop in ("departed", "acked", "reclaimed"):
            assert self.hardware is None and self.owner is None
        if self.stop in ("acked", "reclaimed"):
            assert self.ack == (self.slot, self.pid, self.generation,
                                self.owner_or_last_cpu, self.epoch)
        if self.stop == "reclaimed":
            assert not self.queue and not self.resources and not self.handlers

    def save(self):
        assert self.hardware is not None and self.stop in ("active", "requested", "observed")
        nxt = replace(self, saved=True)
        nxt.check()
        return nxt

    def request_stop(self):
        assert self.stop == "active"
        nxt = replace(self, stop="requested")
        nxt.check()
        return nxt

    def observe_stop(self):
        assert self.stop == "requested" and self.hardware is not None
        nxt = replace(self, stop="observed")
        nxt.check()
        return nxt

    def depart(self):
        assert self.hardware is not None and self.saved
        assert self.stop in ("active", "requested", "observed")
        cpu = self.hardware
        stop = "departed" if self.stop in ("requested", "observed") else "active"
        nxt = replace(self, owner=None, hardware=None, last_cpu=cpu,
                      departed_epoch=self.epoch,
                      stop=stop, ack=None)
        nxt.check()
        return nxt

    def publish(self):
        assert self.hardware is None and self.owner is None
        assert self.stop == "active" and self.saved
        assert self.epoch == self.departed_epoch
        assert not self.queue
        nxt = replace(self, queue=frozenset({self.owner_or_last_cpu}))
        nxt.check()
        return nxt

    def transfer(self, to):
        assert self.stop == "active"
        assert self.hardware is None and self.owner is None
        assert self.saved and self.epoch == self.departed_epoch
        assert self.queue == frozenset({self.owner_or_last_cpu})
        assert to < self.online and to != self.owner_or_last_cpu
        nxt = replace(self, last_cpu=to, queue=frozenset({to}))
        nxt.check()
        return nxt

    def claim(self, cpu):
        assert self.stop == "active" and self.queue == frozenset({cpu})
        assert self.owner is None and self.hardware is None
        nxt = replace(self, owner=cpu, hardware=cpu, last_cpu=cpu,
                      epoch=self.epoch + 1,
                      queue=frozenset(), saved=False)
        nxt.check()
        return nxt

    def acknowledge(self):
        assert self.stop == "departed", "ACK before stop departure"
        assert self.owner is None and self.hardware is None
        token = (self.slot, self.pid, self.generation, self.owner_or_last_cpu, self.epoch)
        nxt = replace(self, stop="acked", ack=token)
        nxt.check()
        return nxt

    def reclaim(self, token):
        assert self.stop == "acked" and self.ack == token
        assert self.owner is None and self.hardware is None and not self.queue
        nxt = replace(self, stop="reclaimed", resources=False, handlers=False)
        nxt.check()
        return nxt


def must_reject(label, operation):
    try:
        operation()
    except (AssertionError, ProtocolError):
        print(f"REJECTED {label}")
        return
    raise AssertionError(f"broken protocol was accepted: {label}")


def safe_migration_and_remote_stop(online):
    task = Task(online=online)
    task.check()
    task = task.save()                   # interrupt/syscall frame saved on A
    task = task.depart()                 # scheduler proves stack/CR3/TSS departed
    task = task.publish()                # runnable membership appears only afterward
    destination = online - 1
    task = task.transfer(destination)    # BKL transaction moves exactly one queue key
    task = task.claim(destination)       # immediate claim consumes that membership
    assert task.state == f"Running{chr(ord('A') + destination)}"
    task = task.request_stop()
    task = task.observe_stop()
    task = task.save()
    task = task.depart()
    token = (task.slot, task.pid, task.generation, destination, task.epoch)
    task = task.acknowledge()
    task = task.reclaim(token)
    assert task.state == "Reclaimed"


def broken_protocols(online):
    base = Task(online=online).save()
    # Mutant bypasses the queue API guard and publishes a second owner while A
    # remains active. The invariant catches execution plus queue membership.
    def early_transfer():
        bad = replace(base, queue=frozenset({online - 1}))
        bad.check()
    must_reject("early-transfer-before-departure", early_transfer)

    # Mutant reports ACK while old hardware still uses the victim context.
    def premature_ack():
        bad = replace(base, stop="acked",
                      ack=(base.slot, base.pid, base.generation, 0, base.epoch))
        bad.check()
    must_reject("premature-ack-before-departure", premature_ack)

    # Mutant duplicates the candidate instead of moving its one queue entry.
    queued = base.depart().publish()
    def duplicate_stolen_owner():
        bad = replace(queued, queue=frozenset({0, online - 1}))
        bad.check()
    must_reject("duplicate-stolen-queue-owner", duplicate_stolen_owner)


def main():
    for online in (2, 4, 6):
        safe_migration_and_remote_stop(online)
        broken_protocols(online)
        print(f"PASS online={online} safe=A->depart->queue->transfer->claim->stop->ACK->reclaim")
    print("MODEL OK counts=2,4,6 mutants_rejected=9")


if __name__ == "__main__":
    main()
