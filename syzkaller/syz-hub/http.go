// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

// collectManagers gathers UIManager data (shared between HTML and JSON endpoints).
func (hub *Hub) collectManagers() ([]UIManager, string) {
	hub.mu.Lock()
	defer hub.mu.Unlock()

	total := UIManager{
		Name:   "total",
		Corpus: len(hub.st.Corpus.Records),
		Repros: len(hub.st.Repros.Records),
	}
	var managers []UIManager
	for name, mgr := range hub.st.Managers {
		total.Added += mgr.Added
		total.Deleted += mgr.Deleted
		total.New += mgr.New
		total.SentRepros += mgr.SentRepros
		total.RecvRepros += mgr.RecvRepros
		dashURL := mgr.HTTP
		if u, ok := hub.dashboards[name]; ok {
			dashURL = u
		}
		um := UIManager{
			Name:       name,
			HTTP:       dashURL,
			Domain:     mgr.Domain,
			Corpus:     len(mgr.Corpus.Records),
			Added:      mgr.Added,
			Deleted:    mgr.Deleted,
			New:        mgr.New,
			SentRepros: mgr.SentRepros,
			RecvRepros: mgr.RecvRepros,
		}
		if v, ok := hub.mgrStats.Load(name); ok {
			ls := v.(*ManagerLiveStats)
			um.Coverage = ls.Coverage
			um.Signal = ls.Signal
			um.Crashes = ls.Crashes
			um.CrashTypes = ls.CrashTypes
			um.ExecTotal = ls.ExecTotal
			if ls.UptimeSec > 0 {
				um.ExecPerSec = ls.ExecTotal / ls.UptimeSec
			}
			um.UptimeSec = ls.UptimeSec
			um.VMsTotal = ls.VMsTotal
			um.VMsAlive = ls.VMsAlive
			um.HasLive = true
			total.Coverage += ls.Coverage
			total.Crashes += ls.Crashes
			total.CrashTypes += ls.CrashTypes
			total.ExecTotal += ls.ExecTotal
			total.ExecPerSec += um.ExecPerSec
			total.VMsTotal += ls.VMsTotal
			total.VMsAlive += ls.VMsAlive
			total.HasLive = true
		}
		managers = append(managers, um)
	}
	sort.Slice(managers, func(i, j int) bool {
		return managers[i].Name < managers[j].Name
	})
	managers = append([]UIManager{total}, managers...)
	return managers, log.CachedLogOutput()
}

func (hub *Hub) httpSummary(w http.ResponseWriter, r *http.Request) {
	managers, logOutput := hub.collectManagers()
	data := &UISummaryData{
		Managers: managers,
		Log:      logOutput,
	}
	if err := summaryTemplate.Execute(w, data); err != nil {
		log.Logf(0, "failed to execute template: %v", err)
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

// httpAPIStats returns JSON for AJAX live-update polling.
func (hub *Hub) httpAPIStats(w http.ResponseWriter, r *http.Request) {
	managers, logOutput := hub.collectManagers()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]any{
		"managers": managers,
		"log":      logOutput,
	})
}

func compileTemplate(html string) *template.Template {
	funcMap := template.FuncMap{
		"uptimeStr": func(sec int) string {
			if sec <= 0 {
				return "0s"
			}
			h := sec / 3600
			m := (sec % 3600) / 60
			if h > 0 {
				return fmt.Sprintf("%dh%02dm", h, m)
			}
			if m > 0 {
				return fmt.Sprintf("%dm%ds", m, sec%60)
			}
			return fmt.Sprintf("%ds", sec)
		},
	}
	return template.Must(template.New("").Funcs(funcMap).Parse(strings.ReplaceAll(html, "{{STYLE}}", htmlStyle)))
}

type UISummaryData struct {
	Managers []UIManager
	Log      string
}

type UIManager struct {
	Name       string
	HTTP       string
	Domain     string
	Corpus     int
	Added      int
	Deleted    int
	New        int
	Repros     int
	SentRepros int
	RecvRepros int
	// Live stats fetched from manager /api/summary.
	Coverage   int
	Signal     int
	Crashes    int
	CrashTypes int
	ExecTotal  int
	ExecPerSec int
	UptimeSec  int
	VMsTotal   int
	VMsAlive   int
	HasLive    bool // true if live stats were successfully fetched
}

// ManagerLiveStats is the JSON response from each manager's /api/summary.
type ManagerLiveStats struct {
	Corpus     int `json:"corpus"`
	Coverage   int `json:"coverage"`
	Signal     int `json:"signal"`
	Crashes    int `json:"crashes"`
	CrashTypes int `json:"crash_types"`
	ExecTotal  int `json:"exec_total"`
	UptimeSec  int `json:"uptime_sec"`
	VMsTotal   int `json:"vms_total"`
	VMsAlive   int `json:"vms_alive"`
}

// normalizeURL replaces any hostname with 127.0.0.1 for local access.
func normalizeURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	rawURL = strings.Replace(rawURL, "://0.0.0.0:", "://127.0.0.1:", 1)
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rest := rawURL[idx+3:]
		if colonIdx := strings.Index(rest, ":"); colonIdx > 0 {
			host := rest[:colonIdx]
			if host != "127.0.0.1" && host != "localhost" {
				rawURL = rawURL[:idx+3] + "127.0.0.1" + rest[colonIdx:]
			}
		}
	}
	return rawURL
}

// fetchManagerStats periodically fetches live stats from each connected manager.
func (hub *Hub) fetchManagerStats() {
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		time.Sleep(1 * time.Second)
		hub.mu.Lock()
		managers := make(map[string]string) // name → HTTP URL
		for name, mgr := range hub.st.Managers {
			// Prefer dashboard URL from cfg file, fallback to manager-reported HTTP.
			if u, ok := hub.dashboards[name]; ok {
				managers[name] = u
			} else if mgr.HTTP != "" {
				managers[name] = normalizeURL(mgr.HTTP)
			}
		}
		hub.mu.Unlock()

		for name, httpURL := range managers {
			url := strings.TrimRight(httpURL, "/") + "/api/summary"
			resp, err := client.Get(url)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			var stats ManagerLiveStats
			if json.Unmarshal(body, &stats) == nil {
				hub.mgrStats.Store(name, &stats)
			}
		}
	}
}

var summaryTemplate = compileTemplate(`
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>PROBE syz-hub</title>
	{{STYLE}}
</head>
<body>

<header>
	<div class="header-inner">
		<div class="brand">
			<span class="logo">&#x25C9;</span>
			<span class="title">PROBE</span>
			<span class="subtitle">syz-hub</span>
		</div>
		<div class="header-right">
			<select id="lang-select" class="lang-select" onchange="switchLang(this.value)">
				<option value="en">English</option>
				<option value="ko">한국어</option>
			</select>
			<div class="status-badge">
				<span class="dot"></span> <span data-en="Active" data-ko="실행 중">Active</span>
			</div>
		</div>
	</div>
</header>

<main>
	{{range $i, $m := $.Managers}}
	{{if eq $i 0}}
	<section class="summary-cards" id="summary-cards">
		<div class="card card-total">
			<div class="card-label" data-en="Total Corpus" data-ko="전체 코퍼스">Total Corpus</div>
			<div class="card-value" id="card-corpus">{{$m.Corpus}}</div>
		</div>
		<div class="card">
			<div class="card-label" data-en="Coverage" data-ko="커버리지">Coverage</div>
			<div class="card-value cyan" id="card-coverage">{{$m.Coverage}}</div>
		</div>
		<div class="card">
			<div class="card-label" data-en="Crashes" data-ko="크래시">Crashes</div>
			<div class="card-value red" id="card-crashes">{{$m.Crashes}}</div>
		</div>
		<div class="card">
			<div class="card-label" data-en="Crash Types" data-ko="크래시 유형">Crash Types</div>
			<div class="card-value red" id="card-crash-types">{{$m.CrashTypes}}</div>
		</div>
		<div class="card">
			<div class="card-label" data-en="Exec/s" data-ko="실행/초">Exec/s</div>
			<div class="card-value green" id="card-execpersec">{{$m.ExecPerSec}}</div>
		</div>
		<div class="card">
			<div class="card-label" data-en="VMs" data-ko="VM 수">VMs</div>
			<div class="card-value yellow" id="card-vms">{{$m.VMsAlive}}/{{$m.VMsTotal}}</div>
		</div>
	</section>
	{{end}}
	{{end}}

	<section class="table-section">
		<h2 data-en="Connected Managers" data-ko="연결된 매니저">Connected Managers</h2>
		<div class="table-wrap">
		<table>
			<thead>
				<tr>
					<th data-en="Name" data-ko="이름">Name</th>
					<th data-en="Dashboard" data-ko="대시보드">Dashboard</th>
					<th class="num" data-en="Coverage" data-ko="커버리지">Coverage</th>
					<th class="num" data-en="Crashes" data-ko="크래시">Crashes</th>
					<th class="num" data-en="Crash Types" data-ko="크래시 유형">Crash Types</th>
					<th class="num" data-en="Exec Total" data-ko="총 실행">Exec Total</th>
					<th class="num" data-en="Exec/s" data-ko="실행/초">Exec/s</th>
					<th class="num" data-en="VMs" data-ko="VM">VMs</th>
					<th class="num" data-en="Uptime" data-ko="가동시간">Uptime</th>
					<th class="num" data-en="Corpus" data-ko="코퍼스">Corpus</th>
					<th class="num" data-en="Added" data-ko="추가">Added</th>
					<th class="num" data-en="New" data-ko="신규">New</th>
					<th class="num" data-en="Repros" data-ko="재현">Repros</th>
				</tr>
			</thead>
			<tbody id="mgr-tbody">
			{{range $i, $m := $.Managers}}
			<tr{{if eq $i 0}} class="row-total"{{end}} data-mgr="{{$m.Name}}">
				<td class="name">{{$m.Name}}</td>
				<td>{{if $m.HTTP}}<a href="{{$m.HTTP}}" target="_blank">{{$m.HTTP}} &#x2197;</a>{{end}}</td>
				<td class="num cyan" data-field="coverage">{{if $m.HasLive}}{{$m.Coverage}}{{else}}-{{end}}</td>
				<td class="num red" data-field="crashes">{{if $m.HasLive}}{{$m.Crashes}}{{else}}-{{end}}</td>
				<td class="num red" data-field="crash_types">{{if $m.HasLive}}{{$m.CrashTypes}}{{else}}-{{end}}</td>
				<td class="num" data-field="exec_total">{{if $m.HasLive}}{{$m.ExecTotal}}{{else}}-{{end}}</td>
				<td class="num green" data-field="exec_per_sec">{{if $m.HasLive}}{{$m.ExecPerSec}}/s{{else}}-{{end}}</td>
				<td class="num yellow" data-field="vms">{{if $m.HasLive}}{{$m.VMsAlive}}/{{$m.VMsTotal}}{{else}}-{{end}}</td>
				<td class="num" data-field="uptime">{{if $m.HasLive}}{{uptimeStr $m.UptimeSec}}{{else}}-{{end}}</td>
				<td class="num" data-field="corpus">{{$m.Corpus}}</td>
				<td class="num green" data-field="added">{{$m.Added}}</td>
				<td class="num cyan" data-field="new">{{$m.New}}</td>
				<td class="num" data-field="repros">{{$m.Repros}}</td>
			</tr>
			{{end}}
			</tbody>
		</table>
		</div>
	</section>

	<section class="log-section">
		<h2 data-en="System Log" data-ko="시스템 로그">System Log</h2>
		<div class="log-wrap">
			<pre id="log_output">{{.Log}}</pre>
		</div>
	</section>
</main>

<footer data-en="PROBE Kernel Fuzzer &mdash; syz-hub corpus exchange" data-ko="PROBE 커널 퍼저 &mdash; syz-hub 코퍼스 교환">PROBE Kernel Fuzzer &mdash; syz-hub corpus exchange</footer>

<script>
	var logEl = document.getElementById("log_output");
	logEl.parentElement.scrollTop = logEl.parentElement.scrollHeight;

	function uptimeStr(sec) {
		if (sec <= 0) return "0s";
		var h = Math.floor(sec / 3600);
		var m = Math.floor((sec % 3600) / 60);
		var s = sec % 60;
		if (h > 0) return h + "h" + String(m).padStart(2,"0") + "m";
		if (m > 0) return m + "m" + s + "s";
		return s + "s";
	}

	function refreshStats() {
		fetch("/api/stats").then(function(r){ return r.json(); }).then(function(data){
			var mgrs = data.managers || [];
			// Update summary cards from total (index 0).
			if (mgrs.length > 0) {
				var t = mgrs[0];
				var ce = document.getElementById("card-corpus");
				if (ce) ce.textContent = t.Corpus;
				var cv = document.getElementById("card-coverage");
				if (cv) cv.textContent = t.Coverage;
				var cr = document.getElementById("card-crashes");
				if (cr) cr.textContent = t.Crashes;
				var ct = document.getElementById("card-crash-types");
				if (ct) ct.textContent = t.CrashTypes;
				var ep = document.getElementById("card-execpersec");
				if (ep) ep.textContent = t.ExecPerSec;
				var vm = document.getElementById("card-vms");
				if (vm) vm.textContent = t.VMsAlive + "/" + t.VMsTotal;
			}
			// Update table rows.
			mgrs.forEach(function(m){
				var row = document.querySelector("tr[data-mgr='" + m.Name + "']");
				if (!row) return;
				var live = m.HasLive;
				function set(field, val) {
					var td = row.querySelector("[data-field='" + field + "']");
					if (td) td.textContent = live ? val : "-";
				}
				set("coverage", m.Coverage);
				set("crashes", m.Crashes);
				set("crash_types", m.CrashTypes);
				set("exec_total", m.ExecTotal);
				set("exec_per_sec", m.ExecPerSec + "/s");
				set("vms", m.VMsAlive + "/" + m.VMsTotal);
				set("uptime", uptimeStr(m.UptimeSec));
				// These don't need HasLive check.
				var corpusTd = row.querySelector("[data-field='corpus']");
				if (corpusTd) corpusTd.textContent = m.Corpus;
				var addedTd = row.querySelector("[data-field='added']");
				if (addedTd) addedTd.textContent = m.Added;
				var newTd = row.querySelector("[data-field='new']");
				if (newTd) newTd.textContent = m.New;
				var reprosTd = row.querySelector("[data-field='repros']");
				if (reprosTd) reprosTd.textContent = m.Repros;
			});
			// Update log.
			if (data.log) {
				var logPre = document.getElementById("log_output");
				var wrap = logPre.parentElement;
				var wasAtBottom = (wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight) < 50;
				logPre.textContent = data.log;
				if (wasAtBottom) wrap.scrollTop = wrap.scrollHeight;
			}
		}).catch(function(){});
	}

	setInterval(refreshStats, 1000);

	function switchLang(lang) {
		document.querySelectorAll("[data-"+lang+"]").forEach(function(el){
			el.innerHTML = el.getAttribute("data-"+lang);
		});
		document.documentElement.lang = lang;
		try { localStorage.setItem("probe-hub-lang", lang); } catch(e){}
	}
	(function(){
		var saved = "en";
		try { saved = localStorage.getItem("probe-hub-lang") || "en"; } catch(e){}
		document.getElementById("lang-select").value = saved;
		if (saved !== "en") switchLang(saved);
	})();
</script>

</body></html>
`)

const htmlStyle = `
	<style>
		*{margin:0;padding:0;box-sizing:border-box}
		body{background:#1a1a2e;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.6}
		header{background:linear-gradient(135deg,#16213e 0%,#0f3460 100%);padding:1rem 2rem;border-bottom:2px solid #e94560}
		.header-inner{max-width:1400px;margin:0 auto;display:flex;align-items:center;justify-content:space-between}
		.brand{display:flex;align-items:center;gap:0.6rem}
		.logo{color:#e94560;font-size:1.6rem}
		.title{color:#fff;font-size:1.4rem;font-weight:700;letter-spacing:1px}
		.subtitle{color:#8892b0;font-size:1rem;font-weight:400}
		.header-right{display:flex;align-items:center;gap:0.8rem}
		.lang-select{background:#16213e;color:#8892b0;border:1px solid #233554;border-radius:6px;padding:4px 8px;font-size:0.8rem;cursor:pointer;outline:none;transition:border-color 0.2s}
		.lang-select:hover,.lang-select:focus{border-color:#57cbff;color:#ccd6f6}
		.lang-select option{background:#16213e;color:#ccd6f6}
		.status-badge{display:flex;align-items:center;gap:0.5rem;background:rgba(255,255,255,0.06);padding:0.4rem 1rem;border-radius:20px;font-size:0.85rem;color:#64ffda}
		.dot{width:8px;height:8px;background:#64ffda;border-radius:50%;display:inline-block;animation:pulse 2s infinite}
		@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
		main{max-width:1400px;margin:1.5rem auto;padding:0 2rem}
		.summary-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}
		.card{background:#16213e;border:1px solid #233554;border-radius:10px;padding:1.2rem;text-align:center;transition:transform 0.2s,border-color 0.2s}
		.card:hover{transform:translateY(-2px);border-color:#e94560}
		.card-total{border-color:#e94560;background:linear-gradient(135deg,#16213e,#1a1a3e)}
		.card-label{font-size:0.8rem;color:#8892b0;text-transform:uppercase;letter-spacing:1px;margin-bottom:0.3rem}
		.card-value{font-size:1.8rem;font-weight:700;color:#ccd6f6}
		.green{color:#64ffda}.red{color:#e94560}.cyan{color:#57cbff}.yellow{color:#ffd700}
		h2{color:#ccd6f6;font-size:1.1rem;margin-bottom:0.8rem;padding-bottom:0.4rem;border-bottom:1px solid #233554}
		.table-section{margin-bottom:2rem}
		.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid #233554}
		table{width:100%;border-collapse:collapse}
		thead{background:#0f3460}
		th{padding:0.7rem 1rem;text-align:left;font-size:0.8rem;color:#8892b0;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap}
		td{padding:0.6rem 1rem;border-top:1px solid #1a2744;font-size:0.9rem;white-space:nowrap}
		th.num,td.num{text-align:right;font-variant-numeric:tabular-nums}
		tbody tr{transition:background 0.15s}
		tbody tr:hover{background:#16213e}
		.row-total{background:#0d1b30;font-weight:600}
		.row-total td{border-top:none;border-bottom:2px solid #233554}
		td.name{font-weight:600;color:#ccd6f6}
		a{color:#57cbff;text-decoration:none}
		a:hover{color:#64ffda;text-decoration:underline}
		.log-section{margin-bottom:2rem}
		.log-wrap{background:#0d1117;border:1px solid #233554;border-radius:8px;max-height:500px;overflow-y:auto;padding:1rem}
		#log_output{font-family:"JetBrains Mono","Fira Code","Cascadia Code",monospace;font-size:0.78rem;line-height:1.5;color:#8b949e;white-space:pre-wrap;word-break:break-all}
		footer{text-align:center;padding:1.5rem;color:#4a5568;font-size:0.8rem;border-top:1px solid #233554}
		@media(max-width:768px){main{padding:0 1rem}.summary-cards{grid-template-columns:repeat(2,1fr)}}
	</style>
`
