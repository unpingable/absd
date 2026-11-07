#!/usr/bin/env python3
"""Independently measure QEMU WAV output; never generate or replace guest audio."""
import argparse,array,json,math,statistics,sys,wave

def measure(path):
    with wave.open(str(path),'rb') as f:
        channels, width, rate, count=f.getnchannels(),f.getsampwidth(),f.getframerate(),f.getnframes()
        if (channels,width,rate)!=(2,2,48000):raise ValueError('expected stereo S16 48000Hz WAV')
        raw=f.readframes(count)
    samples=array.array('h');samples.frombytes(raw)
    if sys.byteorder!='little':samples.byteswap()
    if len(samples)!=count*2:raise ValueError('truncated PCM data')
    active=[i for i in range(count) if samples[2*i]!=0 or samples[2*i+1]!=0]
    if not active:raise ValueError('capture contains no signal')
    first,last=active[0],active[-1]; result=[]
    for c in range(2):
        values=samples[first*2+c:(last+1)*2:2]
        crossings=[]
        for i in range(1,len(values)):
            if values[i-1]<0<=values[i]:crossings.append(i-1-values[i-1]/(values[i]-values[i-1]))
        if len(crossings)<10:raise ValueError('too few tone cycles')
        periods=[b-a for a,b in zip(crossings,crossings[1:])]
        period=round(statistics.median(periods))
        periodic_error=max(abs(values[i]-values[i-period]) for i in range(period,len(values)))
        result.append(dict(frequency_hz=rate/statistics.median(periods),periodic_error=periodic_error,
            period_min=min(periods),period_max=max(periods),peak=max(abs(x) for x in values),
            clipped_samples=sum(abs(x)>=32767 for x in values),
            rms=math.sqrt(sum(x*x for x in values)/len(values))))
    return dict(rate=rate,channels=channels,total_frames=count,first_signal_frame=first,
        last_signal_frame=last,signal_frames=last-first+1,signal_seconds=(last-first+1)/rate,
        channel_measurements=result)

def validate(r):
    failures=[]
    if abs(r['signal_frames']-96000)>1:failures.append('tone signal frame count differs from 96000')
    for c,expected in enumerate([480,800]):
        m=r['channel_measurements'][c]
        if abs(m['frequency_hz']-expected)>0.5:failures.append(f'channel {c} frequency/order')
        if not 7900<=m['peak']<=8100:failures.append(f'channel {c} amplitude')
        if m['clipped_samples']:failures.append(f'channel {c} clipping')
        if m['periodic_error']>1:failures.append(f'channel {c} periodicity/gap')
        if m['period_max']-m['period_min']>1:failures.append(f'channel {c} discontinuity/underrun')
    return failures
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('wav');args=p.parse_args()
    r=measure(args.wav);r['failures']=validate(r);r['verified']=not r['failures']
    print(json.dumps(r,indent=2));sys.exit(0 if r['verified'] else 1)
