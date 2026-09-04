package oracles

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const testNonce = "cafebabe1234"

// writeArtifact 寫入測試 artifact（JSONL）到 t.TempDir 底下的 dir。
func writeArtifact(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("寫入 artifact %s 失敗: %v", name, err)
	}
}

func wantResult(t *testing.T, got Result, err error, wantRefs ...string) {
	t.Helper()
	if err != nil {
		t.Fatalf("Check 回傳非預期錯誤: %v", err)
	}
	want := Result{Result: len(wantRefs) > 0, EvidenceRefs: wantRefs}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Result 不符：got %+v, want %+v", got, want)
	}
}

// ---- nonce_in_field：一正一反 ----

func TestNonceInField(t *testing.T) {
	dir := t.TempDir()
	writeArtifact(t, dir, "sql_trace.jsonl",
		`{"ts":"1","sql":"SELECT * FROM users WHERE name='alice-`+testNonce+`'","params":[],"error":null,"rows":0}`+"\n"+
			`{"ts":"2","sql":"SELECT 1","params":[],"error":null,"rows":0}`+"\n")

	got, err := Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceInField, Field: "sql"}, testNonce, dir)
	if err != nil {
		t.Fatalf("nonce_in_field 正例: %v", err)
	}
	wantResult(t, got, err, "sql_trace.jsonl#1")

	got, err = Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceInField, Field: "sql"}, "notpresent", dir)
	if err != nil {
		t.Fatalf("nonce_in_field 反例: %v", err)
	}
	wantResult(t, got, err) // 未命中：Result=false、refs 空
}

// ---- nonce_statement_errored：良性送達（error=null）必須是 false ----

func TestNonceStatementErrored(t *testing.T) {
	dir := t.TempDir()
	// 第 1 行：sql 含 nonce 但 error=null——良性輸入也會把 nonce 插進 SQL 字面值，
	// 只有語句真的壞掉才成立（§17.3）
	// 第 2 行：sql 含 nonce 且 error 非 null
	// 第 3 行：error 非 null 但 sql 不含 nonce
	writeArtifact(t, dir, "sql_trace.jsonl",
		`{"ts":"1","sql":"SELECT * FROM t WHERE name='alice-`+testNonce+`'","params":[],"error":null,"rows":0}`+"\n"+
			`{"ts":"2","sql":"SELECT * FROM t WHERE name='`+testNonce+`''","params":[],"error":"unrecognized token: \"'`+testNonce+`'\"","rows":0}`+"\n"+
			`{"ts":"3","sql":"SELECT 1","params":[],"error":"unrelated error","rows":0}`+"\n")

	got, err := Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceStatementErrored}, testNonce, dir)
	if err != nil {
		t.Fatalf("nonce_statement_errored: %v", err)
	}
	// 第 1 行（error=null）不得命中；只有第 2 行命中
	wantResult(t, got, err, "sql_trace.jsonl#2")

	// 單獨一個檔案：sql 含 nonce、error=null → false
	dir2 := t.TempDir()
	writeArtifact(t, dir2, "sql_trace.jsonl",
		`{"ts":"1","sql":"SELECT * FROM t WHERE name='alice-`+testNonce+`'","params":[],"error":null,"rows":0}`)
	got, err = Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceStatementErrored}, testNonce, dir2)
	if err != nil {
		t.Fatalf("nonce_statement_errored error=null: %v", err)
	}
	wantResult(t, got, err)

	// 單獨一個檔案：sql 含 nonce、error 非 null → true
	dir3 := t.TempDir()
	writeArtifact(t, dir3, "sql_trace.jsonl",
		`{"ts":"1","sql":"SELECT * FROM t WHERE name='`+testNonce+`''","params":[],"error":"syntax error","rows":0}`)
	got, err = Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceStatementErrored}, testNonce, dir3)
	if err != nil {
		t.Fatalf("nonce_statement_errored error 非 null: %v", err)
	}
	wantResult(t, got, err, "sql_trace.jsonl#1")
}

// ---- rowcount_at_least：一正一反 + json.Number 數值比較 ----

func TestRowCountAtLeast(t *testing.T) {
	dir := t.TempDir()
	// rows 一律以 json.Number 原字面落地（§21.4 規則 2：UseNumber 解碼）
	writeArtifact(t, dir, "sql_trace.jsonl",
		`{"ts":"1","sql":"SELECT * FROM users","params":[],"error":null,"rows":3}`+"\n"+
			`{"ts":"2","sql":"SELECT * FROM users WHERE id=1","params":[],"error":null,"rows":0}`+"\n"+
			`{"ts":"3","sql":"SELECT 2.0","params":[],"error":null,"rows":2.0}`+"\n"+
			`{"ts":"4","sql":"SELECT big","params":[],"error":null,"rows":12345678901234567890}`+"\n")

	// Threshold 3：3 >= 3 命中（第 1 行）；0 與 2.0 未命中；超大整數命中（第 4 行）
	got, err := Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindRowCountAtLeast, Threshold: 3}, testNonce, dir)
	if err != nil {
		t.Fatalf("rowcount_at_least: %v", err)
	}
	wantResult(t, got, err, "sql_trace.jsonl#1", "sql_trace.jsonl#4")

	// Threshold 2：2.0（json.Number 小數字面）>= 2 命中（第 3 行）
	got, err = Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindRowCountAtLeast, Threshold: 2}, testNonce, dir)
	if err != nil {
		t.Fatalf("rowcount_at_least 小數字面: %v", err)
	}
	wantResult(t, got, err, "sql_trace.jsonl#1", "sql_trace.jsonl#3", "sql_trace.jsonl#4")

	got, err = Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindRowCountAtLeast, Threshold: 100}, testNonce, dir)
	if err != nil {
		t.Fatalf("rowcount_at_least 反例: %v", err)
	}
	wantResult(t, got, err, "sql_trace.jsonl#4")

	// rows 為字串（型別不符）→ 未命中，不是錯誤
	dir2 := t.TempDir()
	writeArtifact(t, dir2, "sql_trace.jsonl", `{"ts":"1","sql":"SELECT 1","params":[],"error":null,"rows":"5"}`)
	got, err = Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindRowCountAtLeast, Threshold: 1}, testNonce, dir2)
	if err != nil {
		t.Fatalf("rows 字串型別: %v", err)
	}
	wantResult(t, got, err)
}

// ---- 任意字串欄位三種 kind（listener / dom_event / canary）：一正一反 ----

func TestAnyStringFieldKinds(t *testing.T) {
	cases := []struct {
		kind    ConditionKind
		file    string
		hitJSON string
		// 巢狀字串也要命中（listener 的 query、dom event 的 payload 等）
		nestedJSON string
		missJSON   string
	}{
		{
			kind:       KindListenerRequestWithNonce,
			file:       "listener.jsonl",
			hitJSON:    `{"ts":"1","method":"GET","url":"http://canary-net:8080/x?n=` + testNonce + `","remote":"10.0.0.2"}`,
			nestedJSON: `{"ts":"2","request":{"method":"POST","body":"token=` + testNonce + `","headers":{"X-A":"` + testNonce + `"}}}`,
			missJSON:   `{"ts":"3","method":"GET","url":"http://canary-net:8080/x","remote":"10.0.0.2"}`,
		},
		{
			kind:       KindDOMEventWithNonce,
			file:       "dom_events.jsonl",
			hitJSON:    `{"ts":"1","type":"console","text":"fetched ` + testNonce + `"}`,
			nestedJSON: `{"ts":"2","events":[{"type":"fetch","url":"/api?q=` + testNonce + `"}]}`,
			missJSON:   `{"ts":"3","type":"console","text":"nothing here"}`,
		},
		{
			kind:       KindCanaryFileMatch,
			file:       "canary.jsonl",
			hitJSON:    `{"ts":"1","event":"file_read","path":"/tmp/canary/` + testNonce + `.txt"}`,
			nestedJSON: `{"ts":"2","batch":[{"event":"file_read","path":"/tmp/` + testNonce + `/a"}]}`,
			missJSON:   `{"ts":"3","event":"file_read","path":"/tmp/other.txt"}`,
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			// 正例：單一 entry 命中
			dir := t.TempDir()
			writeArtifact(t, dir, tc.file, tc.hitJSON+"\n")
			got, err := Check(Condition{Artifact: tc.file, Kind: tc.kind}, testNonce, dir)
			if err != nil {
				t.Fatalf("%s 正例: %v", tc.kind, err)
			}
			wantResult(t, got, err, tc.file+"#1")

			// 正例：nonce 藏在巢狀欄位也命中
			dirN := t.TempDir()
			writeArtifact(t, dirN, tc.file, tc.nestedJSON)
			got, err = Check(Condition{Artifact: tc.file, Kind: tc.kind}, testNonce, dirN)
			if err != nil {
				t.Fatalf("%s 巢狀正例: %v", tc.kind, err)
			}
			wantResult(t, got, err, tc.file+"#1")

			// 反例：無 nonce → false
			dirM := t.TempDir()
			writeArtifact(t, dirM, tc.file, tc.missJSON)
			got, err = Check(Condition{Artifact: tc.file, Kind: tc.kind}, testNonce, dirM)
			if err != nil {
				t.Fatalf("%s 反例: %v", tc.kind, err)
			}
			wantResult(t, got, err)
		})
	}
}

// ---- 條件種類封閉集（§17.3：不發明直譯器） ----

func TestConditionKindClosedSet(t *testing.T) {
	if len(ConditionKinds()) != 6 {
		t.Fatalf("v1 條件種類應為 6 種，got %d", len(ConditionKinds()))
	}
	// 未知種類 → error（不得退回 result=false）
	dir := t.TempDir()
	writeArtifact(t, dir, "sql_trace.jsonl", `{"ts":"1","sql":"`+testNonce+`","params":[],"error":null,"rows":0}`)
	got, err := Check(Condition{Artifact: "sql_trace.jsonl", Kind: ConditionKind("regex_in_field"), Field: "sql"}, testNonce, dir)
	if err == nil {
		t.Fatalf("未知條件種類應回傳錯誤，got %+v", got)
	}
	if !strings.Contains(err.Error(), "封閉集") {
		t.Fatalf("錯誤訊息應指出封閉集: %v", err)
	}
	for _, k := range ConditionKinds() {
		if !k.Valid() {
			t.Fatalf("封閉集成員 %q 判定為不合法", k)
		}
	}
}

// ---- SQL trace 欄位閉集（§17.3） ----

func TestSQLTraceFieldClosedSet(t *testing.T) {
	dir := t.TempDir()
	writeArtifact(t, dir, "sql_trace.jsonl", `{"ts":"1","sql":"`+testNonce+`","params":[],"error":null,"rows":0,"extra":"x"}`)
	for _, k := range []ConditionKind{KindNonceInField, KindNonceStatementErrored, KindRowCountAtLeast} {
		cond := Condition{Artifact: "sql_trace.jsonl", Kind: k, Field: "sql", Threshold: 1}
		if _, err := Check(cond, testNonce, dir); err == nil || !strings.Contains(err.Error(), "欄位閉集") {
			t.Fatalf("kind %s 遇未知欄位應報錯: %v", k, err)
		}
	}
	// 非 SQL trace kind 不受欄位閉集約束（listener 等格式不同）
	dir2 := t.TempDir()
	writeArtifact(t, dir2, "listener.jsonl", `{"ts":"1","url":"http://x/`+testNonce+`","custom":"ok"}`)
	if _, err := Check(Condition{Artifact: "listener.jsonl", Kind: KindListenerRequestWithNonce}, testNonce, dir2); err != nil {
		t.Fatalf("listener entry 不應受 sql trace 欄位閉集約束: %v", err)
	}
	if got := SQLTraceFields(); len(got) != 5 || got[0] != "ts" || got[4] != "rows" {
		t.Fatalf("SQL trace 欄位閉集應為 {ts,sql,params,error,rows}: %v", got)
	}
}

// ---- 缺 artifact 檔 → error（環境問題，非未命中） ----

func TestMissingArtifactFile(t *testing.T) {
	dir := t.TempDir()
	got, err := Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceInField, Field: "sql"}, testNonce, dir)
	if err == nil {
		t.Fatalf("缺 artifact 檔應回傳 error，got %+v", got)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("錯誤應包裝 os.ErrNotExist: %v", err)
	}
	if !strings.Contains(err.Error(), "環境問題，非未命中") {
		t.Fatalf("錯誤訊息應區分環境問題與未命中: %v", err)
	}
}

// ---- 條件不合法 → error ----

func TestInvalidCondition(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		cond Condition
		nonce string
	}{
		{"缺 artifact", Condition{Kind: KindNonceInField, Field: "sql"}, testNonce},
		{"artifact 含路徑", Condition{Artifact: "../etc/passwd", Kind: KindNonceInField, Field: "sql"}, testNonce},
		{"nonce_in_field 缺 field", Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceInField}, testNonce},
		{"nonce 為空", Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceInField, Field: "sql"}, ""},
		{"artifactsDir 為空", Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceInField, Field: "sql"}, testNonce},
	}
	for i, tc := range cases {
		d := dir
		if tc.name == "artifactsDir 為空" {
			d = ""
		}
		if _, err := Check(tc.cond, tc.nonce, d); err == nil {
			t.Fatalf("case %d（%s）應回傳 error", i, tc.name)
		}
	}
}

// ---- EvidenceRefs 格式與多行解析 ----

func TestEvidenceRefsFormatAndMultiLine(t *testing.T) {
	dir := t.TempDir()
	// 6 行（含一個空行）：第 1、4、6 行含 nonce（第 3 行為空行，仍佔行號）
	writeArtifact(t, dir, "sql_trace.jsonl",
		`{"ts":"1","sql":"a `+testNonce+` b","params":[],"error":null,"rows":0}`+"\n"+
			`{"ts":"2","sql":"clean","params":[],"error":null,"rows":0}`+"\n"+
			"\n"+
			`{"ts":"3","sql":"x `+testNonce+` y","params":[],"error":null,"rows":0}`+"\n"+
			`{"ts":"4","sql":"clean2","params":[],"error":null,"rows":0}`+"\n"+
			`{"ts":"5","sql":"z `+testNonce+`","params":[],"error":null,"rows":0}`)

	got, err := Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceInField, Field: "sql"}, testNonce, dir)
	if err != nil {
		t.Fatalf("多行解析: %v", err)
	}
	want := []string{"sql_trace.jsonl#1", "sql_trace.jsonl#4", "sql_trace.jsonl#6"}
	if !reflect.DeepEqual(got.EvidenceRefs, want) {
		t.Fatalf("EvidenceRefs 應為 %v（空行仍佔行號），got %v", want, got.EvidenceRefs)
	}
	re := regexp.MustCompile(`^sql_trace\.jsonl#[1-9][0-9]*$`)
	for _, ref := range got.EvidenceRefs {
		if !re.MatchString(ref) {
			t.Fatalf("EvidenceRef %q 不符 \"artifact#行號\" 格式", ref)
		}
	}
	if !got.Result {
		t.Fatalf("有命中時 Result 應為 true")
	}
}

// ---- 不合法 JSONL → error（artifact 內容問題，非未命中） ----

func TestMalformedJSONL(t *testing.T) {
	dir := t.TempDir()
	writeArtifact(t, dir, "sql_trace.jsonl", `{"ts":"1","sql":"ok"}`+"\n"+`not json`)
	if _, err := Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceInField, Field: "sql"}, testNonce, dir); err == nil {
		t.Fatalf("不合法 JSONL 應回傳 error")
	}
	// JSON array 也不是 object
	dir2 := t.TempDir()
	writeArtifact(t, dir2, "sql_trace.jsonl", `[1,2,3]`)
	if _, err := Check(Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceInField, Field: "sql"}, testNonce, dir2); err == nil {
		t.Fatalf("JSON array 行應回傳 error")
	}
}

// ---- CheckRule：包裝 Check ----

func TestCheckRule(t *testing.T) {
	dir := t.TempDir()
	writeArtifact(t, dir, "sql_trace.jsonl",
		`{"ts":"1","sql":"SELECT * FROM t WHERE name='`+testNonce+`''","params":[],"error":"syntax error","rows":0}`)

	r := Rule{
		OracleID: "sqli.error/v1",
		Family:   "sqli",
		Touch:    "sink.touch.sql/v1",
		Rule:     Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceStatementErrored},
	}
	got, err := CheckRule(r, testNonce, dir)
	if err != nil {
		t.Fatalf("CheckRule: %v", err)
	}
	wantResult(t, got, err, "sql_trace.jsonl#1")

	// touch rule（paired）本身也可判定
	touch := Rule{OracleID: "sink.touch.sql/v1", Family: "sqli", Rule: Condition{Artifact: "sql_trace.jsonl", Kind: KindNonceInField, Field: "sql"}}
	got, err = CheckRule(touch, testNonce, dir)
	if err != nil {
		t.Fatalf("CheckRule touch: %v", err)
	}
	wantResult(t, got, err, "sql_trace.jsonl#1")
}