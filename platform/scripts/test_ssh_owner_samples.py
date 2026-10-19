#!/usr/bin/env python3
"""Exact owner-sample comparison rule; other image changes still count."""
import pathlib
import types
import unittest
from unittest.mock import patch
import agent_warm
import cports_warm
import ssh_absd

class OwnerSampleObjects(unittest.TestCase):
    def objects(self, sample=b'a'*512, sample_path='/var/log/network-status', readonly=False, directory=False, extra=None, missing=False, sample_serial=7):
        def record(data, ro=False, is_dir=False):
            return {'dir':is_dir,'readonly':ro,'serial':7,'size':len(data),'data':data}
        rows={'/etc/motd':record(b'fixed',True), '/var/log/fsd':record(b'changing log')}
        if not missing:
            rows[sample_path]=record(sample,readonly,directory)
            rows[sample_path]['serial']=sample_serial
        if extra:rows.update(extra)
        target=ssh_absd.AbsdTarget.__new__(ssh_absd.AbsdTarget);target.image=pathlib.Path('/unused/image')
        with patch.object(ssh_absd.absd_fs,'fs_region',return_value=object()), \
             patch.object(ssh_absd.absd_fs,'select',return_value=object()), \
             patch.object(ssh_absd.absd_fs,'tree',return_value=rows), \
             patch.object(ssh_absd.absd_fs,'content',side_effect=lambda region,selected,r:r['data']):
            return target.system_objects()
    def test_only_declared_bounded_sample_content_changes_are_ignored(self):
        first=self.objects();second=self.objects(sample=b'b'*512,sample_serial=37)
        self.assertEqual(first,second)
        self.assertEqual([row[0] for row in first],['/etc/motd','/var/log/network-status'])
        self.assertTrue(all(len(row)==5 for row in first))
    def test_missing_sample_changes_comparison(self):
        self.assertNotEqual(self.objects(),self.objects(missing=True))
    def test_recovery_projection_keeps_its_exact_shape_and_presence(self):
        kwargs={'sample_path':'/var/log/network-recovery','sample':b'a'*128}
        before=self.objects(**kwargs)
        self.assertEqual(before,self.objects(**dict(kwargs,sample=b'b'*128,sample_serial=37)))
        for changed in [{'missing':True},{'sample':b'a'*127},{'sample':b'a'*129},
                        {'readonly':True},{'directory':True}]:
            with self.subTest(changed=changed):
                self.assertNotEqual(before,self.objects(**dict(kwargs,**changed)))
    def test_other_serial_changes_are_still_detected(self):
        changed=self.objects(extra={'/etc/motd':{'dir':False,'readonly':True,'serial':8,'size':5,'data':b'fixed'}})
        self.assertNotEqual(changed,self.objects())
    def test_existing_consumer_views_retain_presence_and_shape(self):
        def views(rows):
            target=types.SimpleNamespace(system_objects=lambda:rows)
            rehearsal=agent_warm.Rehearsal.__new__(agent_warm.Rehearsal)
            rehearsal.t=types.SimpleNamespace(target=target)
            return rehearsal.state(),cports_warm.target_state(types.SimpleNamespace(t=target),None)
        baseline=views(self.objects())
        self.assertEqual(baseline,views(self.objects(sample=b'b'*512,sample_serial=37)))
        for kwargs in [{'missing':True},{'sample':b'a'*511},{'readonly':True},{'directory':True}]:
            with self.subTest(kwargs=kwargs):
                for before,after in zip(baseline,views(self.objects(**kwargs))):
                    self.assertNotEqual(before,after)
    def test_wrong_size_readonly_and_directory_samples_remain_in_comparison(self):
        for kwargs in [{'sample':b'a'*511},{'sample':b'a'*513},{'readonly':True},
                       {'directory':True},
                       {'sample':b'','directory':True,'sample_path':'/var/log/network-status/'}]:
            with self.subTest(kwargs=kwargs):
                paths=[row[0] for row in self.objects(**kwargs)]
                self.assertTrue(any(path.startswith('/var/log/network-status') for path in paths))
                self.assertNotEqual(self.objects(**kwargs),self.objects())
    def test_neighbor_path_and_protected_content_changes_are_still_detected(self):
        neighbor=self.objects(sample_path='/var/log/network-status.other')
        self.assertIn('/var/log/network-status.other',[row[0] for row in neighbor])
        changed=self.objects(extra={'/etc/motd':{'dir':False,'readonly':True,'serial':7,'size':7,'data':b'changed'}})
        self.assertNotEqual(changed,self.objects())

if __name__=='__main__':unittest.main()
