package journal

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegis-dev/aegis/internal/domain"
	"github.com/aegis-dev/aegis/internal/evidence"
	"github.com/aegis-dev/aegis/internal/schemav"
)

// openTest 在 t.TempDir() 開一個 journal，測試結束自動關閉。
func openTest(t *testing.T) *Journal {
	t.Helper()
	j, err := Open(filepath.Join(t.TempDir(), "journal.sqlite"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { j.Close() })
	return j
}

// TestOpenWAL 驗證 journal 檔以 WAL 模式開啟（§16）。
func TestOpenWAL(t *testing.T) {
	j := openTest(t)
	var mode string
	if err := j.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("讀 journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q，預期 wal", mode)
	}
}

// TestReopenPreserves 同檔重開不重置：事件保留、schema_version 不被改寫、序號續號。
func TestReopenPreserves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.sqlite")
	j, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := j.Append("run_started", "", nil); err != nil {
		t.Fatalf("Append: %v", err)
	}
	id1, err := j.NextID("F")
	if err != nil {
		t.Fatalf("NextID: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	j2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer j2.Close()

	events, err := j2.Events()
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 1 || events[0].Type != "run_started" {
		t.Fatalf("重開後事件不符：%+v", events)
	}
	if got, err := j2.NextID("F"); err != nil || got == id1 {
		t.Fatalf("重開後序號未續號：got %q、舊 %q（err=%v）", got, id1, err)
	}
	var sv string
	if err := j2.db.QueryRow(
		`SELECT value FROM meta WHERE key = 'schema_version'`,
	).Scan(&sv); err != nil {
		t.Fatalf("讀 schema_version: %v", err)
	}
	if sv != domain.SchemasVersion {
		t.Fatalf("schema_version = %q，預期 %q", sv, domain.SchemasVersion)
	}
}

// TestAppendUnknownType 拒絕閉集外的事件型別（§21.3）。
func TestAppendUnknownType(t *testing.T) {
	j := openTest(t)
	if _, err := j.Append("not_a_type", "", nil); err == nil {
		t.Fatal("未知事件型別應回錯")
	} else if !strings.Contains(err.Error(), "未知事件型別") {
		t.Fatalf("錯誤訊息應標明未知事件型別：%v", err)
	}
	for _, et := range domain.JournalEventTypes {
		if _, err := j.Append(et, "", nil); err != nil {
			t.Fatalf("閉集成員 %q 不應回錯：%v", et, err)
		}
	}
}

// TestAppendFindingIDFormat finding_id 非空時須為 F-####（schema 約束）。
func TestAppendFindingIDFormat(t *testing.T) {
	j := openTest(t)
	if _, err := j.Append("finding_created", "EV-0001", nil); err == nil {
		t.Fatal("finding_id=EV-0001 應回錯")
	}
	if _, err := j.Append("finding_created", "F-0001", nil); err != nil {
		t.Fatalf("finding_id=F-0001 不應回錯：%v", err)
	}
}

// TestNextIDSequence 連續分配 F-0001→F-0002→F-0003（§21.2 zero-pad 4）。
func TestNextIDSequence(t *testing.T) {
	j := openTest(t)
	want := []string{"F-0001", "F-0002", "F-0003"}
	for _, w := range want {
		got, err := j.NextID("F")
		if err != nil {
			t.Fatalf("NextID(F): %v", err)
		}
		if got != w {
			t.Fatalf("NextID(F) = %q，預期 %q", got, w)
		}
	}
}

// TestNextIDCrossPrefix 跨前綴互不干擾，各自從 0001 起算（§21.2）。
func TestNextIDCrossPrefix(t *testing.T) {
	j := openTest(t)
	if got, err := j.NextID("F"); err != nil || got != "F-0001" {
		t.Fatalf("NextID(F) = %q（err=%v）", got, err)
	}
	for _, tc := range []struct{ prefix, want string }{
		{"EV", "EV-0001"}, {"R", "R-0001"}, {"GR", "GR-0001"},
	} {
		got, err := j.NextID(tc.prefix)
		if err != nil {
			t.Fatalf("NextID(%s): %v", tc.prefix, err)
		}
		if got != tc.want {
			t.Fatalf("NextID(%s) = %q，預期 %q", tc.prefix, got, tc.want)
		}
	}
	if got, err := j.NextID("F"); err != nil || got != "F-0002" {
		t.Fatalf("NextID(F) 應為 F-0002：got %q（err=%v）", got, err)
	}
}

// TestNextIDUnknownPrefix 拒絕閉集外前綴（§21.2）。
func TestNextIDUnknownPrefix(t *testing.T) {
	j := openTest(t)
	if _, err := j.NextID("SN"); err == nil {
		t.Fatal("前綴 SN 應回錯")
	}
}

// TestEventsRoundTrip 事件讀回：seq/type/finding_id/ts 保留，payload 數值以
// json.Number 原字面 round-trip（§21.4 規則 2）。
func TestEventsRoundTrip(t *testing.T) {
	j := openTest(t)
	payload := map[string]any{
		"confidence": json.Number("0.80"),
		"count":      int64(7),
		"non_ascii":  "鍵排序測試",
		"nested":     map[string]any{"ok": true, "note": "<b>&"},
	}
	seq, err := j.Append("triage_updated", "", payload)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	events, err := j.Events()
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("事件數 = %d，預期 1", len(events))
	}
	e := events[0]
	if e.Seq != seq {
		t.Fatalf("seq = %d，預期 %d", e.Seq, seq)
	}
	if e.Type != "triage_updated" || e.FindingID != "" {
		t.Fatalf("type/finding_id 不符：%q / %q", e.Type, e.FindingID)
	}
	if e.Ts.IsZero() || e.Ts.Location() != time.UTC {
		t.Fatalf("ts 應為 UTC 非零時間：%v", e.Ts)
	}
	if e.SchemaVersion != domain.SchemasVersion {
		t.Fatalf("schema_version = %q", e.SchemaVersion)
	}
	if got, ok := e.Payload["confidence"].(json.Number); !ok || got != json.Number("0.80") {
		t.Fatalf("confidence 應為 json.Number 原字面 0.80：%#v", e.Payload["confidence"])
	}
	if got, ok := e.Payload["count"].(json.Number); !ok || got != json.Number("7") {
		t.Fatalf("count 應為 json.Number 7：%#v", e.Payload["count"])
	}
	nested, ok := e.Payload["nested"].(map[string]any)
	if !ok || nested["ok"] != true {
		t.Fatalf("nested 未正確還原：%#v", e.Payload["nested"])
	}
}

// TestPayloadCanonical 儲存即 canonical JSON：與 evidence.CanonicalBytes 輸出 byte 相等。
func TestPayloadCanonical(t *testing.T) {
	j := openTest(t)
	payload := map[string]any{
		"b": 2, "a": 1, "html": "<&>",
		"中": "文字",
	}
	if _, err := j.Append("stage_completed", "", payload); err != nil {
		t.Fatalf("Append: %v", err)
	}
	var raw string
	if err := j.db.QueryRow(`SELECT payload FROM events WHERE seq = 1`).Scan(&raw); err != nil {
		t.Fatalf("讀 payload: %v", err)
	}
	want, err := evidence.CanonicalBytes(payload)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if raw != string(want) {
		t.Fatalf("payload 非 canonical：\ngot  %s\nwant %s", raw, want)
	}
	// 兩次序列化 byte 相等（§21.4 驗收）。
	again, err := evidence.CanonicalBytes(payload)
	if err != nil || string(again) != string(want) {
		t.Fatalf("canonical 序列化不穩定")
	}
}

// TestEventsSchemaCompat 用 schemav 對樣本事件驗證 schemas/journal_event.schema.json
// （機讀真源，§5：不得只依範例推測）。
func TestEventsRoundTripSchema(t *testing.T) {
	j := openTest(t)
	if _, err := j.Append("finding_created", "F-0001", map[string]any{
		"sink": map[string]any{"file": "app/db.py", "line": int64(88)},
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := j.Append("run_started", "", nil); err != nil {
		t.Fatalf("Append: %v", err)
	}

	reg := schemav.New()
	if err := reg.LoadDir("/Users/mac/Documents/code/aiproject/SITCON-hacker-zone/schemas"); err != nil {
		t.Fatalf("載入 schemas： %v", err)
	}
	events, err := j.Events()
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	for _, e := range events {
		// 組成 journal_event 物件：finding_id 為空時省略（schema 該欄有 pattern 約束）。
		obj := map[string]any{
			"seq":            e.Seq,
			"type":           e.Type,
			"ts":             e.Ts.Format(time.RFC3339Nano),
			"schema_version": e.SchemaVersion,
			"payload":        e.Payload,
		}
		if e.FindingID != "" {
			obj["finding_id"] = e.FindingID
		}
		data, err := json.Marshal(obj)
		if err != nil {
			t.Fatalf("marshal 事件： %v", err)
		}
		if err := reg.Validate("journal_event", data); err != nil {
			t.Fatalf("事件不符 journal_event schema（seq=%d）：%v", e.Seq, err)
		}
	}
}