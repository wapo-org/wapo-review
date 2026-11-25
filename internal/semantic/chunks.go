package semantic

import "github.com/wapo-org/wapo-review/internal/ast"

type CodeChunk = ast.CodeChunk

func ExtractChunks(path string, src []byte) ([]CodeChunk, error) {
	f, e := ast.ExtractFileFacts(path, src)
	if e != nil {
		return nil, e
	}
	return f.Chunks, nil
}
