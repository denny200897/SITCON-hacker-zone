package orchestrator

// 臨時 adversarial repro（P1-4）：對「目前」的字串搜尋版 ASTCheck 證明文字層假命中。
// 修復後本檔刪除，正式測試移入 astcheck_test.go。

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScratchTextualFalsePositiveRepro(t *testing.T) {
	dir := t.TempDir()
	// 只有 UserRepoX（前綴）與註解／字串常數出現 "class UserRepo"／"find_by_name"，
	// 真正的 UserRepo 類不存在——文字層會假命中，AST 解析必須拒絕。
	app := `
NOTE = "class UserRepo: def find_by_name(self, name): pass"  # 字串常數（假命中來源）
# class UserRepo 的設計筆記：find_by_name 尚未實作（註解假命中來源）
class UserRepoX:
    def find_by_name(self, name):
        return name
`
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(app), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ASTCheck(dir, "app.UserRepo.find_by_name"); err == nil {
		t.Fatalf("P1-4 repro：文字層假命中應被拒絕（symbol app.UserRepo.find_by_name 不存在）")
	}
}
