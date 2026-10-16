package out

// Column sets (design §6). Changing one changes the analysis contract:
// add columns at the end and bump SchemaVersion.

// SchemaVersion is recorded in meta.json.
const SchemaVersion = 1

var QueryCols = []string{
	"run_id", "arm", "query_seq", "ts_start", "due_lag_ms",
	"conn_id", "conn_slot", "conn_gen", "namespace", "query_key",
	"conn_query_n", "conn_objects_n", "conn_age_s", "host_pid", "host_query_n",
	"deadline_ms", "latency_ms", "exec_ms", "first_row_ms", "enum_ms",
	"rows", "objects_read", "props_read", "array_props_read", "array_elems_read",
	"status", "hr", "scode", "wcode", "eff_code", "err_op", "err_src", "err_text",
	"enum_end_hr", "items_skipped", "props_failed", "panics",
	"sta_tid", "apt_type", "apt_ok", "ledger_acquired", "ledger_outstanding", "ledger_double", "ledger_leaked",
	"target_pid", "truth_kind", "truth_lo", "truth_hi", "truth_missing", "truth_phantom", "truth_mismatch", "silent_mask",
	"canary_us",
}

var ConnCols = []string{
	"run_id", "arm", "ts", "conn_id", "prev_conn_id", "conn_slot", "conn_gen", "namespace",
	"event", "reason", "sta_start_ms", "connect_ms", "security_ms",
	"hr", "scode", "wcode", "err_op", "err_text",
	"queries_at_event", "objects_at_event", "age_s", "ledger_outstanding", "ledger_double",
}

var ProcCols = []string{
	"ts", "role", "pid", "create_time", "image", "account", "host_label",
	"private_bytes", "working_set", "handles", "threads", "cpu_kernel_ms", "cpu_user_ms",
	"go_heap_alloc", "go_heap_sys", "goroutines", "num_gc", "modules_hash", "services_in_host",
}

var HostCols = []string{
	"ts", "cpu_total_pct", "cpu_induced_pct", "avail_phys_mb", "avail_phys_pct", "commit_mb", "commit_limit_mb",
	"disk_free_gb", "canary_us",
	"queries_total", "ok_total", "errors_total", "abandoned_total", "overloaded_total", "noconn_total", "hung_now", "inflight",
	"s1_total", "s2_total", "s3_total", "s4_total", "s5_total",
	"connects_total", "connect_fail_total", "recycles_total", "recycles_by_reason",
	"wmiprvse_count", "wmiprvse_exits_total", "sched_scheduled", "sched_dropped",
}

var EventCols = []string{"ts", "kind", "slot", "conn_id", "pid", "detail"}

var TruthCols = []string{"ts", "query_seq", "query_key", "kind", "missing_keys", "phantom_keys", "registry_count", "note"}

// Schemas maps file base names to their columns.
func Schemas() map[string][]string {
	return map[string][]string{
		"queries": QueryCols, "connections": ConnCols, "procs": ProcCols,
		"host": HostCols, "events": EventCols, "truth": TruthCols,
	}
}
