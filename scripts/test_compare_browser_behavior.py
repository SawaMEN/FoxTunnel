import copy
import unittest

import compare_browser_behavior as behavior


class BrowserBehaviorEvidence(unittest.TestCase):
    def report(self, protocol='h2', resumed=False):
        wire = dict(hello={name:[1, 2] for name in behavior.VECTORS},
                    initial_h2_settings=[{'id':4,'value':65535},{'id':1,'value':4096}])
        phases = {name:dict(started=n, finished=0 if name=='cancel' else n,
                           canceled=n if name=='cancel' else 0, active=0,
                           max_active=n if name in ('parallel','cancel') else 1)
                  for name,n in behavior.EXPECTED.items()}
        connections = []
        for i in range(3):
            requests = {k:v for k,v in behavior.EXPECTED.items() if k!='reconnect'} if i==0 else {'reconnect':1}
            c = dict(id=i+1, alpn=protocol, session_resumed=resumed and i>0, requests=requests)
            if protocol=='h2': c['h2_wire']=copy.deepcopy(wire)
            connections.append(c)
        return dict(schema=1,kind='controlled-browser-behavior',protocol=protocol,
                    complete=True,rotations=2,client_failed=False,phases=phases,connections=connections)

    def test_missing_cancellation_reconnect_and_wire_evidence_rejected(self):
        base = self.report()
        for mutate in (
                lambda r:r['phases']['cancel'].update(canceled=3),
                lambda r:r['phases']['parallel'].update(max_active=1),
                lambda r:r['connections'][2]['requests'].update(reconnect=2),
                lambda r:r['connections'][0].pop('session_resumed'),
                lambda r:r['connections'][0].pop('h2_wire'),
                lambda r:r.update(complete=False)):
            r=copy.deepcopy(base);mutate(r)
            with self.assertRaises(ValueError): behavior.validate(r,'h2')

    def test_presence_and_order_are_distinct(self):
        a=self.report()['connections'][0]['h2_wire'];b=copy.deepcopy(a)
        b['hello']['extensions'].reverse();b['initial_h2_settings'].reverse()
        rows=behavior.ordered_vectors(a,b)
        for row in (rows[0],rows[-1]):
            self.assertTrue(row['same_presence']);self.assertFalse(row['same_order'])

    def test_resumption_difference_is_observed_without_equivalence_score(self):
        profiles={(s,p):self.report(p,resumed=s=='firefox') for s in ('firefox','foxtunnel') for p in ('h2','h3')}
        cold={(s,'h3'):{} for s in ('firefox','foxtunnel')}
        result=behavior.compare(profiles,cold)
        for case in result['cases']:
            self.assertEqual(case['firefox']['resumed_connections'],2)
            self.assertEqual(case['foxtunnel']['resumed_connections'],0)
        self.assertEqual(result['h3_raw_order'],'not_measured')
        self.assertNotIn('score',result)
        del profiles[('firefox','h3')]
        with self.assertRaises(ValueError): behavior.compare(profiles,cold)


if __name__=='__main__': unittest.main()
