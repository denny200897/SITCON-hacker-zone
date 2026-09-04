// Package journal 實作 SQLite event journal（SPEC §4 Snapshot 與執行一致性、§21.2、§21.3）。
// 以 modernc.org/sqlite（純 Go、無 cgo）經 database/sql，PRAGMA journal_mode=WAL（§16）。
// finding／evidence／run／guardrail 的 ID 一律由本套件以 SQL 交易（BEGIN IMMEDIATE）分配，
// 各處不得自取（§21.2）。
package journal

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/aegis-dev/aegis/internal/domain"
	"github.com/aegis-dev/aegis/internal/evidence"

	// 純 Go SQLite driver（§16：單 binary 交叉編譯的前提）。
	_ "modernc.org/sqlite"
)

// driverName 是 database/sql 註冊的 driver 名稱（modernc.org/sqlite）。
const driverName = "sqlite"

// idPrefixes 是可由 journal 分配的 ID 前綴閉集（§21.2：F／EV／R／GR）。
var idPrefixes = map[string]bool{
	"F":  true, // finding
	"EV": true, // evidence
	"R":  true, // run
	"GR": true, // guardrail
}

// Event 是 journal 的一列事件（與 schemas/journal_event.schema.json 相容）。
// Payload 一律經 UseNumber 解碼（§21.4 規則 2：json.Number 原字面 round-trip）。
type Event struct {
	Seq           int64
	Type          string
	FindingID     string
	Ts            time.Time
	Payload       map[string]any
	SchemaVersion string
}

// Journal 包住單一 SQLite 檔的 event journal。
type Journal struct {
	db *sql.DB
}

// Open 開啟（或建立）path 下的 journal 檔，建表並確認 WAL。
// journal 記 schema_version（目前為 domain.SchemasVersion）；同檔重開不重置，
// 既有版本與程式版本不符時回錯（升版須附遷移，§4 schema 版本化）。
func Open(path string) (*Journal, error) {
	// _txlock=immediate：所有交易以 BEGIN IMMEDIATE 起始（NextID 的併發安全前提，§21.2）；
	// busy_timeout：WAL 下寫鎖競爭時等待而非立即回錯。
	dsn := "file:" + path + "?_txlock=immediate&_pragma=busy_timeout(5000)"
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("journal: open %s: %w", path, err)
	}
	j := &Journal{db: db}
	// v1 單一寫入連線即可（§23-1 禁並行），同時避免多連線鎖競爭。
	db.SetMaxOpenConns(1)

	if err := j.ensureWAL(); err != nil {
		db.Close()
		return nil, err
	}
	if err := j.createTables(); err != nil {
		db.Close()
		return nil, err
	}
	if err := j.ensureSchemaVersion(); err != nil {
		db.Close()
		return nil, err
	}
	return j, nil
}

// ensureWAL 設定並驗證 journal_mode=WAL（§16）。
func (j *Journal) ensureWAL() error {
	if _, err := j.db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return fmt.Errorf("journal: set journal_mode=wal: %w", err)
	}
	var mode string
	if err := j.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		return fmt.Errorf("journal: read journal_mode: %w", err)
	}
	if mode != "wal" {
		return fmt.Errorf("journal: journal_mode=%s，預期 wal", mode)
	}
	return nil
}

// createTables 建表（IF NOT EXISTS：同檔重開不重置）。
func (j *Journal) createTables() error {
	stmts := []string{
		// meta：journal 自身的中繼資料（schema_version 等）。
		`CREATE TABLE IF NOT EXISTS meta (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		// events：append-only 事件列；seq 由 AUTOINCREMENT 保證 monotonic 不重用。
		`CREATE TABLE IF NOT EXISTS events (
			seq            INTEGER PRIMARY KEY AUTOINCREMENT,
			type           TEXT NOT NULL,
			finding_id     TEXT NOT NULL DEFAULT '',
			ts             TEXT NOT NULL,
			schema_version TEXT NOT NULL,
			payload        TEXT NOT NULL
		)`,
		// id_alloc：ID 序列（§21.2）；prefix 為 F／EV／R／GR，next 是下一個要發的號碼。
		`CREATE TABLE IF NOT EXISTS id_alloc (
			prefix TEXT PRIMARY KEY,
			next   INTEGER NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := j.db.Exec(s); err != nil {
			return fmt.Errorf("journal: create table: %w", err)
		}
	}
	return nil
}

// ensureSchemaVersion 記錄 schema_version（首次）並於重開時比對，不符即拒開。
func (j *Journal) ensureSchemaVersion() error {
	if _, err := j.db.Exec(
		`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
		 ON CONFLICT(key) DO NOTHING`,
		domain.SchemasVersion,
	); err != nil {
		return fmt.Errorf("journal: record schema_version: %w", err)
	}
	var got string
	if err := j.db.QueryRow(
		`SELECT value FROM meta WHERE key = 'schema_version'`,
	).Scan(&got); err != nil {
		return fmt.Errorf("journal: read schema_version: %w", err)
	}
	if got != domain.SchemasVersion {
		return fmt.Errorf("journal: schema_version 不相容（journal=%s、程式=%s）；升版須附遷移",
			got, domain.SchemasVersion)
	}
	return nil
}

// Append 追加一筆事件並回傳其 seq。
// eventType 必須是 domain.JournalEventTypes 成員（§21.3 閉集），未知 type 回錯；
// findingID 可為空，非空時須為 F-#### 形式（schemas/journal_event.schema.json 的約束）；
// payload 以 canonical JSON（evidence.CanonicalBytes，§21.4）儲存，nil 視為空物件。
func (j *Journal) Append(eventType, findingID string, payload map[string]any) (int64, error) {
	if !domain.IsJournalEventType(eventType) {
		return 0, fmt.Errorf("journal: 未知事件型別 %q（§21.3 閉集）", eventType)
	}
	if findingID != "" {
		prefix, _, err := domain.ParseID(findingID)
		if err != nil || prefix != "F" {
			return 0, fmt.Errorf("journal: finding_id 須為 F-#### 形式，得 %q", findingID)
		}
	}
	if payload == nil {
		payload = map[string]any{}
	}
	raw, err := evidence.CanonicalBytes(payload)
	if err != nil {
		return 0, fmt.Errorf("journal: canonical payload: %w", err)
	}

	res, err := j.db.Exec(
		`INSERT INTO events (type, finding_id, ts, schema_version, payload)
		 VALUES (?, ?, ?, ?, ?)`,
		eventType, findingID, time.Now().UTC().Format(time.RFC3339Nano),
		domain.SchemasVersion, string(raw),
	)
	if err != nil {
		return 0, fmt.Errorf("journal: insert event: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("journal: last insert id: %w", err)
	}
	return seq, nil
}

// NextID 以 SQL 交易（BEGIN IMMEDIATE，經 _txlock=immediate）分配下一個
// prefix-#### 的 ID（§21.2：monotonic、zero-pad 4、journal 統一分配）。
// 序列（v1 無 goroutine 並行）下也照此實作，M2 並行時不用改（§21.2）。
func (j *Journal) NextID(prefix string) (string, error) {
	if !idPrefixes[prefix] {
		return "", fmt.Errorf("journal: 未知 ID 前綴 %q（§21.2 閉集：F／EV／R／GR）", prefix)
	}
	tx, err := j.db.Begin() // _txlock=immediate ⇒ BEGIN IMMEDIATE
	if err != nil {
		return "", fmt.Errorf("journal: begin tx: %w", err)
	}
	defer tx.Rollback() // 已 commit 後為 no-op

	var next int64
	err = tx.QueryRow(`SELECT next FROM id_alloc WHERE prefix = ?`, prefix).Scan(&next)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		next = 1
		if _, err := tx.Exec(
			`INSERT INTO id_alloc (prefix, next) VALUES (?, ?)`, prefix, next+1,
		); err != nil {
			return "", fmt.Errorf("journal: init id_alloc %s: %w", prefix, err)
		}
	case err != nil:
		return "", fmt.Errorf("journal: read id_alloc %s: %w", prefix, err)
	default:
		if _, err := tx.Exec(
			`UPDATE id_alloc SET next = ? WHERE prefix = ?`, next+1, prefix,
		); err != nil {
			return "", fmt.Errorf("journal: bump id_alloc %s: %w", prefix, err)
		}
	}
	if next > 9999 {
		return "", fmt.Errorf("journal: 前綴 %s 序號超出 zero-pad 4 上限（§21.2）", prefix)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("journal: commit id_alloc %s: %w", prefix, err)
	}
	return domain.FormatID(prefix, int(next)), nil
}

// Events 依 seq 順序回傳全部事件；payload 經 UseNumber 解碼（§21.4 規則 2）。
func (j *Journal) Events() ([]Event, error) {
	rows, err := j.db.Query(
		`SELECT seq, type, finding_id, ts, schema_version, payload
		 FROM events ORDER BY seq`,
	)
	if err != nil {
		return nil, fmt.Errorf("journal: query events: %w", err)
	}
	defer rows.Close()

	events := []Event{}
	for rows.Next() {
		var e Event
		var tsStr, payloadRaw string
		if err := rows.Scan(&e.Seq, &e.Type, &e.FindingID, &tsStr, &e.SchemaVersion, &payloadRaw); err != nil {
			return nil, fmt.Errorf("journal: scan event: %w", err)
		}
		e.Ts, err = time.Parse(time.RFC3339Nano, tsStr)
		if err != nil {
			return nil, fmt.Errorf("journal: parse ts %q: %w", tsStr, err)
		}
		e.Payload, err = evidence.Decode([]byte(payloadRaw))
		if err != nil {
			return nil, fmt.Errorf("journal: decode payload seq=%d: %w", e.Seq, err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("journal: iterate events: %w", err)
	}
	return events, nil
}

// Close 關閉底層資料庫連線。
func (j *Journal) Close() error {
	if err := j.db.Close(); err != nil {
		return fmt.Errorf("journal: close: %w", err)
	}
	return nil
}