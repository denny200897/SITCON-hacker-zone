// Package schemav 載入 schemas/*.schema.json 並驗證資料（§5：schema 為唯一機讀真源）。
// 使用 santhosh-tekuri/jsonschema/v6（draft 2020-12，§16 固定決策）。
package schemav

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// baseID 與 schemas/*.json 的 $id 一致；$ref 以相對路徑解析到同一 base 下。
const baseID = "https://aegis.dev/schemas/"

// Registry 持有已載入的 schemas，支援 $ref 跨檔解析（以 $id 引用）。
type Registry struct {
	mu     sync.Mutex
	byName map[string]*jsonschema.Schema
}

// New 建立空 registry。
func New() *Registry {
	return &Registry{byName: map[string]*jsonschema.Schema{}}
}

// LoadDir 讀取目錄下所有 *.schema.json，編譯並註冊（name = 去副檔名檔名）。
func (r *Registry) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("schemav: read %s: %w", dir, err)
	}
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	type loaded struct {
		name string
		url  string
		doc  any
	}
	docs := []loaded{}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("schemav: read %s: %w", name, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("schemav: unmarshal %s: %w", name, err)
		}
		// 以檔案自身的 $id 註冊（$ref 相對路徑才會解析到同一 base 下）
		url := baseID + name
		if m, ok := doc.(map[string]any); ok {
			if id, ok := m["$id"].(string); ok && id != "" {
				url = id
			}
		}
		docs = append(docs, loaded{name: name, url: url, doc: doc})
	}

	comp := jsonschema.NewCompiler()
	comp.UseLoader(disabledLoader{})
	for _, d := range docs {
		if err := comp.AddResource(d.url, d.doc); err != nil {
			return fmt.Errorf("schemav: add resource %s: %w", d.name, err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range docs {
		sch, err := comp.Compile(d.url)
		if err != nil {
			return fmt.Errorf("schemav: compile %s: %w", d.name, err)
		}
		r.byName[d.name] = sch
	}
	return nil
}

// Validate 驗證資料是否符合指定 name（如 "finding"）的 schema。
// 資料以 json.Decoder＋UseNumber 解碼後驗證（hash 相容性，§21.4）。
func (r *Registry) Validate(name string, data []byte) error {
	r.mu.Lock()
	sch := r.byName[name+".schema.json"]
	r.mu.Unlock()
	if sch == nil {
		return fmt.Errorf("schemav: schema %q not loaded", name)
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("schemav: decode: %w", err)
	}
	if err := sch.Validate(v); err != nil {
		return fmt.Errorf("schemav: %s: %w", name, err)
	}
	return nil
}

// disabledLoader 阻擋任何外部 schema 載入（全部資源來自 schemas/ 目錄）。
type disabledLoader struct{}

func (disabledLoader) Load(string) (any, error) {
	return nil, fmt.Errorf("schemav: external schema loading disabled")
}