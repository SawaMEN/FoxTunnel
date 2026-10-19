package multihop

import (
	"testing"
	"time"
)

func q(delay float64, now time.Time) Measurement {
	return Measurement{Samples: 5, LatencyMS: delay, LastSuccess: now}
}

func TestDirectWinsColdStartAndRelayIsExplored(t *testing.T) {
	now := time.Now()
	routes := []Candidate{{ID:"hub", Direct:true}, {ID:"relay"}}
	s := State{}
	for i:=0;i<5;i++ {
		var index int
		index,s=Select(routes,s,now)
		if index!=0 {t.Fatalf("cold start decision %d selected %d", i,index)}
	}
	index,s:=Select(routes,s,now)
	if index!=1 {t.Fatalf("sixth real operation should explore relay, got %d",index)}
	if s.Preferred!="" {t.Fatal("unmeasured exploration established preference")}
}

func TestDirectAndRelayMeasuredHysteresis(t *testing.T) {
	now:=time.Now()
	routes:=[]Candidate{
		{ID:"hub", Direct:true, Quality:q(85,now)},
		{ID:"relay", Quality:q(20,now)},
	}
	s:=State{Preferred:"hub",Since:now.Add(-5*time.Second)}
	index,s:=Select(routes,s,now)
	if index!=0 {t.Fatalf("premature switching: %d",index)}
	s.Since=now.Add(-time.Minute)
	index,s=Select(routes,s,now)
	if index!=1||s.Preferred!="relay" {t.Fatalf("obvious relay improvement ignored: %d %+v",index,s)}
	routes[0].Quality.LatencyMS=15
	index,_=Select(routes,State{Preferred:"relay",Since:now.Add(-time.Minute)},now)
	if index!=1 {t.Fatalf("insufficient improvement triggered switch: %d",index)}
}

func TestDirectPreferredOnSimilarLatency(t *testing.T) {
	now:=time.Now()
	routes:=[]Candidate{{ID:"hub",Direct:true,Quality:q(25,now)},{ID:"relay",Quality:q(24,now)}}
	index,s:=Select(routes,State{},now)
	if index!=0||s.Preferred!="hub" {t.Fatalf("added relay not justified: %d %+v",index,s)}
}

func TestCooldownAndFallbackNoReplay(t *testing.T) {
	now:=time.Now()
	routes:=[]Candidate{
		{ID:"hub", Direct:true,Quality:q(10,now),RetryAt:now.Add(25*time.Second)},
		{ID:"relay",Quality:q(45,now)},
	}
	index,_:=Select(routes,State{Preferred:"hub",Since:now},now)
	if index!=1 {t.Fatalf("cooling direct selected: %d",index)}
	routes[1].Tried=true
	index,_=Select(routes,State{},now)
	if index!=0 {t.Fatalf("failed to try only remaining route: %d",index)}
	routes[0].Tried=true
	index,_=Select(routes,State{},now)
	if index!=-1 {t.Fatalf("already-tried origin reused: %d",index)}
}

func TestUnknownAndStaleMeasurements(t *testing.T) {
	now:=time.Now()
	routes:=[]Candidate{
		{ID:"hub",Direct:true,Quality:q(65,now)},
		{ID:"relay",Quality:Measurement{Samples:2,LatencyMS:5,LastSuccess:now}},
	}
	index,_:=Select(routes,State{},now)
	if index!=0 {t.Fatalf("insufficient relay measurements: %d",index)}
	routes[1].Quality=q(3,now.Add(-3*time.Minute))
	index,_=Select(routes,State{},now)
	if index!=0 {t.Fatalf("stale relay selected: %d",index)}
}

func TestMeasurementSkipsLongPolls(t *testing.T) {
	now:=time.Now()
	m:=Update(Measurement{},250*time.Millisecond,false,now)
	if m.Samples!=1||m.LatencyMS!=250 {t.Fatal(m)}
	m=Update(m,0,false,now.Add(time.Second))
	if m.Samples!=1 {t.Fatal("idle poll contaminated estimator")}
	m=Update(m,0,true,now.Add(time.Second))
	if m.Samples!=1||m.FailurePct<=0 {t.Fatal("failure reporting lost sample integrity")}
	m=Update(m,50*time.Millisecond,false,now.Add(time.Second))
	if m.Samples!=2||m.LatencyMS>=250||m.JitterMS<=0 {t.Fatal(m)}
}
