// Command probe2 is the correct-client WMI degradation probe (design:
// docs/probe-v2-design.md).
//
//	probe2 preflight [flags]   per-host checks; writes preflight.json
//	probe2 run -arm NAME ...   one arm
//	probe2 version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"wmiresearch/probe/internal/abort"
	"wmiresearch/probe/internal/catalog"
	"wmiresearch/probe/internal/etw"
	"wmiresearch/probe/internal/isolation"
	"wmiresearch/probe/internal/preflight"
	"wmiresearch/probe/internal/runner"
	"wmiresearch/probe/internal/strategy"
	"wmiresearch/probe/internal/sysinfo"
)

// commit is set at build time: -ldflags "-X main.commit=<sha>".
var commit = "dev"

// priority is the process priority class as started, and its change.
var priority string

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	if os.Args[1] == "run" || os.Args[1] == "preflight" {
		if priority, err = sysinfo.NormalPriority(); err != nil {
			log.Printf("priority %s: %v", priority, err)
		}
	}
	switch os.Args[1] {
	case "run":
		err = cmdRun(ctx, os.Args[2:])
	case "preflight":
		err = cmdPreflight(ctx, os.Args[2:])
	case "wmiwatch":
		err = cmdWMIWatch(ctx, os.Args[2:])
	case "version":
		fmt.Println("probe2", commit)
	default:
		usage()
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: probe2 run|preflight|wmiwatch|version [flags]  (probe2 run -h for flags)")
	os.Exit(2)
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

// startMeter starts the ETW foreign-WMI meter. A meter that cannot start is
// recorded, not fatal: the arm's foreign-WMI validity is then unknown.
func startMeter(ctx context.Context, on, period time.Duration) (*etw.Meter, string, func()) {
	if on <= 0 {
		return nil, "off", func() {}
	}
	m, err := etw.NewMeter(on, period)
	if err != nil {
		log.Printf("ETW meter unavailable: %v", err)
		return nil, "unavailable: " + err.Error(), func() {}
	}
	mctx, cancel := context.WithCancel(ctx)
	go m.Run(mctx)
	return m, fmt.Sprintf("on %s every %s", on, period), func() {
		cancel()
		if err := m.Close(); err != nil {
			log.Printf("ETW meter close: %v", err)
		}
	}
}

// cmdWMIWatch prints WMI operation starts by client process (ETW, no WMI
// calls): a quick check of what else uses WMI on a host.
func cmdWMIWatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("wmiwatch", flag.ExitOnError)
	dur := fs.Duration("duration", time.Minute, "how long to watch")
	every := fs.Duration("every", 10*time.Second, "print interval")
	_ = fs.Parse(args)
	m, desc, stop := startMeter(ctx, time.Hour, time.Hour)
	defer stop()
	if m == nil {
		return errors.New(desc)
	}
	end := time.Now().Add(*dur)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*every):
		}
		d := m.Drain()
		log.Printf("on %.0fs: self %d foreign %d internal %d lost %d %s", d.OnFor.Seconds(), d.Self, d.Foreign, d.Internal, d.Lost, d.Enabling)
		for _, c := range d.Counts {
			if !c.Self {
				log.Printf("  pid %d %s local=%v internal=%v ops %d: %s", c.ClientPID, c.Image, c.Local, c.Internal, c.Ops, c.Sample)
			}
		}
	}
	return nil
}

func runID() string { return time.Now().UTC().Format("20060102T150405Z") }

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	arm := fs.String("arm", "", "arm name (ST-1, H, L, E1, ...; buggy arms must start with buggy-)")
	outRoot := fs.String("out", `C:\probe\results`, "results root; the run writes <out>/<host>/<arm>/<run_id>/")
	host := fs.String("host", hostname(), "host label in the results path")
	k := fs.Float64("k", 1, "acceleration factor: every query runs at k x its production rate")
	dur := fs.Duration("duration", 0, "arm duration (required)")
	strat := fs.String("strategy", "none", "none | timed | adaptive | pool")
	timed := fs.Duration("timed-interval", time.Hour, "reconnect interval for -strategy timed")
	deadline := fs.Duration("deadline", 30*time.Second, "per-call deadline (abandoned at it under adaptive and pool)")
	mix := fs.String("mix", "production", "production | stress")
	cimv2 := fs.Int("cimv2-conns", 0, "root\\cimv2 connections (default 3; 16 with -mix stress)")
	skipNS := fs.String("skip-ns", "", "comma-separated namespaces to leave out")
	only := fs.String("only", "", "comma-separated query keys to keep (focused runs)")
	seed := fs.Int64("seed", 1, "schedule seed")
	class := fs.String("client-class", "correct", "correct | buggy")
	bug := fs.String("bug", "", "buggy only: array-leak | cross-apartment")
	pf := fs.String("preflight", "", "preflight.json: provider attribution, and absent namespaces are skipped")
	sample := fs.Duration("sample-interval", 10*time.Second, "resource sample interval")
	hangWarn := fs.Duration("hang-warn", 10*time.Minute, "flag a call running this long")
	hangAbort := fs.Duration("hang-abort", 60*time.Minute, "abort the arm when a call runs this long (0 = never)")
	etwOn := fs.Duration("etw-on", time.Minute, "ETW foreign-WMI meter: on this long per period (0 = no meter)")
	etwPeriod := fs.Duration("etw-period", 15*time.Minute, "ETW meter duty-cycle period")
	release := fs.Duration("release-test", 0, "after the arm, close all connections and keep sampling this long (ST-3)")
	truthOn := fs.Bool("truth", true, "check results against non-WMI ground truth")
	maxInduced := fs.Float64("max-induced-cpu", abort.Defaults().MaxInducedCPUPct, "abort when probe-induced CPU stays above this % for 10 min")
	allowForeign := fs.Bool("allow-foreign-wmi", false, "run even if WMI-heavy software (e.g. the Esinta agent) is running; recorded in meta")
	memLimit := fs.Int64("gomemlimit-mb", 256, "Go heap soft limit (MB)")
	_ = fs.Parse(args)

	if *dur <= 0 || *arm == "" {
		return errors.New("-arm and -duration are required")
	}
	debug.SetMemoryLimit(*memLimit << 20)

	qs, err := catalog.ByName(*mix)
	if err != nil {
		return err
	}
	var attribution map[string]string
	var skip []string
	if *skipNS != "" {
		skip = strings.Split(*skipNS, ",")
	}
	if *pf != "" {
		p, err := preflight.Load(*pf)
		if err != nil {
			return fmt.Errorf("preflight: %w", err)
		}
		attribution = p.Attribution
		skip = append(skip, p.Absent()...)
	}
	qs = catalog.Without(qs, skip)
	if *only != "" {
		qs = catalog.Only(qs, strings.Split(*only, ","))
	}
	st, err := strategy.Parse(*strat, *timed)
	if err != nil {
		return err
	}
	if *cimv2 == 0 {
		*cimv2 = 3
		if *mix == "stress" {
			*cimv2 = 16
		}
	}

	findings, err := isolation.Check()
	if err != nil {
		return fmt.Errorf("isolation check: %w", err)
	}
	argv := append([]string{"run"}, args...)
	if len(findings) > 0 {
		for _, f := range findings {
			log.Printf("isolation: %s %s running (%s)", f.Kind, f.Name, f.Why)
		}
		if !*allowForeign {
			return errors.New("host is not isolated: stop the software above or pass -allow-foreign-wmi (the run is then marked)")
		}
		argv = append(argv, "#isolation-overridden")
	}

	lim := abort.Defaults()
	lim.MaxInducedCPUPct = *maxInduced
	cfg := runner.Config{
		Arm: *arm, Host: *host, OutRoot: *outRoot, RunID: runID(), ClientClass: *class, Bug: *bug,
		Mix: *mix, Queries: qs, K: *k, Duration: *dur, Seed: *seed, Strategy: st, Deadline: *deadline, Cimv2Conns: *cimv2,
		SampleInterval: *sample, HangWarn: *hangWarn, HangAbort: *hangAbort, ReleaseTest: *release, Truth: *truthOn,
		Attribution: attribution, Limits: lim, Commit: commit, Priority: priority, Args: argv,
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	log.Printf("arm %s: k=%g (%.0f queries/h), %s, strategy %s, %d namespaces, output %s",
		cfg.Arm, cfg.K, cfg.K*catalog.PerHourTotal(qs), cfg.Duration, st.Kind, len(catalog.Namespaces(qs)), cfg.Dir())
	env := runner.NativeEnv(*outRoot, attribution)
	meter, desc, stopMeter := startMeter(ctx, *etwOn, *etwPeriod)
	defer stopMeter()
	if meter != nil {
		env.Meter = meter
	}
	env.MeterDesc = desc
	sum, err := runner.Run(ctx, cfg, env)
	log.Printf("end: %s; queries %d ok %d errors %d abandoned %d; silent S1..S5 %d/%d/%d/%d/%d; recycles %d; induced CPU %.1f %%",
		sum.EndReason, sum.Totals["queries"], sum.Totals["ok"], sum.Totals["errors"], sum.Totals["abandoned"],
		sum.Totals["s1"], sum.Totals["s2"], sum.Totals["s3"], sum.Totals["s4"], sum.Totals["s5"], sum.Totals["recycles"], sum.MeanInducedCPU)
	return err
}

func cmdPreflight(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("preflight", flag.ExitOnError)
	outRoot := fs.String("out", `C:\probe\results`, "results root; writes <out>/<host>/preflight/<run_id>/")
	host := fs.String("host", hostname(), "host label")
	idle := fs.Duration("idle", 60*time.Minute, "idle baseline before any WMI call")
	unload := fs.Duration("unload-watch", 30*time.Minute, "watch provider hosts this long after releasing all connections")
	ramp := fs.String("ramp", "", "comma-separated k values for the calibration ramp (e.g. 1,5,10,20,50,100); empty = no ramp")
	step := fs.Duration("ramp-step", 10*time.Minute, "duration of each ramp step")
	budget := fs.Float64("ramp-budget", 40, "max mean probe-induced CPU % for k_H")
	_ = fs.Parse(args)

	var ks []float64
	if *ramp != "" {
		for _, s := range strings.Split(*ramp, ",") {
			v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
			if err != nil || v <= 0 {
				return fmt.Errorf("bad -ramp value %q", s)
			}
			ks = append(ks, v)
		}
	}
	findings, err := isolation.Check()
	if err != nil {
		return err
	}
	for _, f := range findings {
		log.Printf("isolation: %s %s running (%s): this host is not clean", f.Kind, f.Name, f.Why)
	}
	meter, desc, stopMeter := startMeter(ctx, time.Hour, time.Hour) // always on in pre-flight
	defer stopMeter()
	res, dir, err := preflight.Run(ctx, preflight.Config{
		Meter: meter, MeterDesc: desc,
		OutRoot: *outRoot, Host: *host, RunID: runID(), Idle: *idle, UnloadWatch: *unload,
		Ramp: ks, RampStep: *step, RampBudget: *budget, Commit: commit, Priority: priority, Log: log.Printf,
	})
	if res != nil {
		log.Printf("preflight written to %s", dir)
		log.Printf("account %s; OS %s %s; %d namespaces checked; %d classes attributed", res.Account, res.OS.ProductName, res.OS.Build, len(res.Namespaces), len(res.Attribution))
		log.Printf("H-enum: %s", res.HEnum.Verdict)
		if len(res.Ramp) > 0 {
			log.Printf("k_H = %g", res.KH)
		}
		for _, n := range res.Notes {
			log.Printf("note: %s", n)
		}
	}
	return err
}
