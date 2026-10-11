#!/usr/bin/env python3
"""Bounded fixture construction, not RT scheduling policy or public admission."""
from dataclasses import dataclass, replace
import json
@dataclass(frozen=True)
class Child:
    slot:int; pid:int; pending_pid:int; mode:int
    seq:int=0; first:int=10; wake:int=10; configured:bool=False

def arm(c,parent_waiting,now,mutant=''):
    if not parent_waiting and mutant!='arm-before-sleep': raise ValueError('parent runnable')
    if c.pid!=c.pending_pid and mutant!='stale-slot': raise ValueError('stale PID')
    if c.configured and mutant!='rearm': return c
    if c.seq and mutant!='rearm': raise ValueError('already released')
    first=now+10+(4 if c.mode==13 else 0)
    if mutant=='independent-phase' and c.mode==13:first+=4
    return replace(c,first=first,wake=first+(15 if c.mode==8 else 20 if c.mode==11 else 0),configured=True)
def release(c,tick,mutant=''):
    if not c.configured and mutant!='release-pending': return c
    if tick>=c.first:return replace(c,seq=c.seq+1)
    return c
def wake(c,tick,mutant=''):
    return bool(tick>=c.wake and (c.configured or mutant=='wake-pending'))
def cancel(c,old_pid,mutant=''):
    return None if c.pid==old_pid or mutant=='stale-cancel' else c

def properties(mutant=''):
    n=0
    for mode in [1,8,9,10,11,13]:
      for tick in [0,10,20,25,100]:
        c=Child(2,41,41,mode); assert release(c,tick,mutant).seq==0
        assert not wake(c,tick,mutant)
        a=arm(c,True,100,mutant);assert a.first==110+(4 if mode==13 else 0)
        assert a.wake==a.first+(15 if mode==8 else 20 if mode==11 else 0)
        assert arm(a,True,200,mutant)==a
        try:arm(c,False,100,mutant)
        except ValueError:pass
        else:raise AssertionError('armed while parent runnable')
        stale=replace(c,pid=42)
        try:arm(stale,True,100,mutant)
        except ValueError:pass
        else:raise AssertionError('stale slot armed successor')
        assert cancel(stale,41,mutant)==stale
        assert cancel(c,41,mutant) is None
        n+=1
    return n
out={'scope':'closed RT fixture; unique boot PIDs, same kernel serialization, no public authority or real hardware proof','positive_states':properties(),'controls':{}}
for m in ['arm-before-sleep','stale-slot','rearm','release-pending','wake-pending','independent-phase','stale-cancel']:
 try:properties(m)
 except (AssertionError,ValueError) as e:out['controls'][m]={'rejected':True,'witness':str(e)}
 else:raise AssertionError('surviving control '+m)
print(json.dumps(out,indent=2))
