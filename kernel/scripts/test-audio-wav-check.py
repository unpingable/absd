#!/usr/bin/env python3
import array,importlib.util,math,tempfile,unittest,wave
from pathlib import Path
spec=importlib.util.spec_from_file_location('wavcheck',Path(__file__).with_name('audio-wav-check.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class WavCheck(unittest.TestCase):
    def capture(self,frames=96000,frequencies=(480,800),amplitude=8000):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);p=Path(tmp.name)/'capture.wav'
        # Independent sine fixture, deliberately unlike the guest triangle generator.
        data=array.array('h',(round(amplitude*math.sin(2*math.pi*f*i/48000)) for i in range(frames) for f in frequencies))
        if m.sys.byteorder!='little':data.byteswap()
        with wave.open(str(p),'wb') as w:w.setparams((2,2,48000,0,'NONE','not compressed'));w.writeframes(data.tobytes())
        return p
    def test_valid_distinct_channels(self):self.assertEqual(m.validate(m.measure(self.capture())),[])
    def test_truncated_tail_is_not_a_pass(self):self.assertIn('tone signal frame count differs from 96000',m.validate(m.measure(self.capture(frames=95556))))
    def test_gap_between_zero_crossings_is_not_a_pass(self):
        p=self.capture()
        with wave.open(str(p),'rb') as w:params=w.getparams();data=bytearray(w.readframes(w.getnframes()))
        data[10*4:15*4]=bytes(20)
        with wave.open(str(p),'wb') as w:w.setparams(params);w.writeframes(data)
        self.assertIn('channel 0 periodicity/gap',m.validate(m.measure(p)))
    def test_swapped_channels_are_not_a_pass(self):self.assertIn('channel 0 frequency/order',m.validate(m.measure(self.capture(frequencies=(800,480)))))
    def test_silence_is_not_a_pass(self):
        with self.assertRaisesRegex(ValueError,'no signal'):m.measure(self.capture(amplitude=0))
    def test_wrong_amplitude_is_not_a_pass(self):self.assertIn('channel 0 amplitude',m.validate(m.measure(self.capture(amplitude=4000))))
if __name__=='__main__':unittest.main()
