#!/usr/bin/env python3
"""Finite publication/store-buffer model, not an ARM ISA or complete C++ model.

Two actors, one publication, bounded atomic words. Release publication cannot
become visible before prior words; Acquire prevents consuming speculative reads
from before publication. SC store/load operations share one total order. All
assumptions and counterexample event histories are exported.
"""
import argparse
import collections
import hashlib
import json
import subprocess
from pathlib import Path

CASES = {
    'message-passing': 1,
    'queue-handoff': 3,
    'ownership-token': 3,
    'generation-replacement': 2,
    'task-stop-observation': 3,
    'refcount-reclaim': 1,
    'wake-after-state': 2,
    'lock-handoff': 1,
    'object-visibility': 4,
}

def publication(words, release, acquire):
    # written count, propagated bits, publication consumed, read bits, values.
    initial = (0, 0, False, 0, 0)
    queue = collections.deque([initial]); parents = {initial: None}
    all_words = (1 << words) - 1; forbidden = None; terminals = 0
    while queue:
        state = queue.popleft(); written, visible, consumed, reads, values = state
        if consumed and reads == all_words:
            terminals += 1
            if values != all_words and forbidden is None:
                forbidden = state
        actions = []
        if written <= words:
            actions.append((f'writer issue word {written}' if written < words else 'writer issue publication', (written+1, visible, consumed, reads, values)))
        for i in range(min(written, words+1)):
            if visible & (1 << i): continue
            if i == words and release and visible & all_words != all_words: continue
            actions.append((f'propagate {"publication" if i == words else "word " + str(i)}', (written, visible | (1 << i), consumed, reads, values)))
        if visible & (1 << words) and not consumed:
            actions.append(('reader consume publication', (written, visible, True, reads, values)))
        if consumed or not acquire:
            for i in range(words):
                if not reads & (1 << i):
                    bit = visible & (1 << i)
                    actions.append((f'reader {"consume" if consumed else "speculate"} word {i}={int(bool(bit))}', (written, visible, consumed, reads | (1 << i), values | bit)))
        for event, successor in actions:
            if successor not in parents:
                parents[successor] = (state, event); queue.append(successor)
    history = []
    if forbidden is not None:
        while parents[forbidden] is not None:
            forbidden, event = parents[forbidden]; history.append(event)
        history.reverse()
    return dict(states=len(parents), terminal_states=terminals, forbidden=bool(history), counterexample=history)

def store_load(sc):
    # Two program counters; issued and propagated writes; result -1 unset.
    initial=(0,0,0,0,-1,-1)
    queue=collections.deque([initial]);parents={initial:None};bad=None;terminals=0
    while queue:
        s=queue.popleft();a,b,issued,visible,r0,r1=s
        if a==b==2:
            terminals+=1
            if r0==r1==0 and bad is None:bad=s
        actions=[]
        for cpu,pc in enumerate((a,b)):
            if pc==2:continue
            pcs=[a,b];pcs[cpu]+=1;results=[r0,r1]
            if pc==0:
                new_issued=issued|(1<<cpu);new_visible=visible|(1<<cpu)if sc else visible
                event=f'CPU{cpu} issue store'+(' globally ordered'if sc else ' buffered')
            else:
                results[cpu]=int(bool(visible&(1<<(1-cpu))));new_issued=issued;new_visible=visible
                event=f'CPU{cpu} load peer={results[cpu]}'
            actions.append((event,(*pcs,new_issued,new_visible,*results)))
        if not sc:
            for cpu in range(2):
                if issued&(1<<cpu) and not visible&(1<<cpu):actions.append((f'propagate CPU{cpu} store',(a,b,issued,visible|(1<<cpu),r0,r1)))
        for event,n in actions:
            if n not in parents:parents[n]=(s,event);queue.append(n)
    history=[]
    if bad is not None:
        while parents[bad]is not None:bad,event=parents[bad];history.append(event)
        history.reverse()
    return dict(states=len(parents),terminal_states=terminals,forbidden=bool(history),counterexample=history)

def stop_fence(require_departure):
    initial=(False,False,False,False,False)
    queue=collections.deque([initial]);seen={initial};bad=[]
    while queue:
        s=queue.popleft();request,observed,departed,ack,reclaimed=s
        if reclaimed and not departed:bad.append(s)
        allowed=[not request,request and not observed,observed and not departed,observed and not ack and (departed or not require_departure),ack and not reclaimed]
        for i,yes in enumerate(allowed):
            if yes:
                n=list(s);n[i]=True;n=tuple(n)
                if n not in seen:seen.add(n);queue.append(n)
    return dict(states=len(seen),forbidden=bool(bad),counterexamples=bad)

def peer_routing(per_peer):
    # Sequentially consistent interleavings suffice to expose the old routing
    # error. CPU2 must not consume the old CPU1 sequence with CPU2's next target.
    # writer PC, reader PC, visible sequence, target, sampled sequence, accepted.
    initial=(0,0,0 if per_peer else 1,2 if per_peer else 1,-1,False)
    queue=collections.deque([initial]);parents={initial:None};bad=None;terminals=0
    while queue:
        s=queue.popleft();w,r,sequence,target,sample,accepted=s
        if r==2:
            terminals+=1
            if accepted and sample!=2 and bad is None:bad=s
        actions=[]
        if w==0:actions.append(('publisher prepare CPU2 metadata',(1,r,sequence,2,sample,accepted)))
        if w==1:actions.append(('publisher release CPU2 ticket2',(2,r,2,target,sample,accepted)))
        if r==0:
            actions.append(('CPU2 acquire ticket',(w,2 if sequence==0 else 1,sequence,target,sequence,False)))
        if r==1:
            actions.append(('CPU2 consume destination',(w,2,sequence,target,sample,target==2)))
        for event,n in actions:
            if n not in parents:parents[n]=(s,event);queue.append(n)
    history=[]
    if bad is not None:
        while parents[bad]is not None:bad,event=parents[bad];history.append(event)
        history.reverse()
    return dict(states=len(parents),terminal_states=terminals,forbidden=bool(history),counterexample=history)

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    rows=[]
    for name,words in CASES.items():
        good=publication(words,True,True);no_release=publication(words,False,True);no_acquire=publication(words,True,False)
        assert not good['forbidden'] and no_release['forbidden'] and no_acquire['forbidden'],name
        rows.append(dict(case=name,words=words,positive=good,negative_no_release=no_release,negative_no_acquire=no_acquire))
    good=store_load(True);bad=store_load(False);assert not good['forbidden'] and bad['forbidden']
    rows.append(dict(case='store-load-publication',positive=good,negative_buffered_store_load=bad))
    good=stop_fence(True);bad=stop_fence(False);assert not good['forbidden'] and bad['forbidden']
    rows.append(dict(case='departure-before-reclaim',positive=good,negative_early_ack=bad))
    good=peer_routing(True);bad=peer_routing(False);assert not good['forbidden'] and bad['forbidden']
    rows.append(dict(case='peer-ticket-generation-routing',positive=good,negative_shared_ticket_next_target=bad))
    base=Path(__file__).resolve().parents[2]
    sources=['src/owner_lock.rs','src/arch/aarch64/litmus.rs','src/arch/aarch64/smp.rs','src/process.rs']
    record=dict(schema_version=1,source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=base,text=True).strip(),model_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),source_files={s:hashlib.sha256((base/s).read_bytes()).hexdigest()for s in sources},disposition='PASS',cases=rows,assumptions=['Two actors, one publication, finite atomic words; no cycles, ABA, wrapping generations or competing publishers','Release visibility and Acquire speculation exclusion are explicit model axioms','SC operations share one global order; relaxed buffered stores may propagate after later loads','Refcount case represents one releasing decrementation consumed by the last acquiring reference; does not model an arbitrary release sequence','Lock case represents visibility at unlock/acquire; no relaxed Rust data-race execution is admitted','Stop fence is an abstract five-phase protocol; hardware root/stack departure must be established separately at runtime'],not_earned=['Complete ARM/C++ memory model proof','Automatic source/model equivalence','Multicore hardware coverage beyond named HVF runs'])
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(record,indent=2)+'\n')
    print(f'ARM weak-memory model PASS: {len(rows)} positive cases; 21 deterministic negative cases')
if __name__=='__main__':main()
