package agent

import (
	"context"
	"encoding/json"
	"fmt"

	einomcp "github.com/cloudwego/eino-ext/components/tool/mcp"
	"github.com/cloudwego/eino/components/tool"
	"github.com/mark3labs/mcp-go/client"
)

// MCPTools adapts an initialized MCP client. The client must be created with
// only the credentials authorized for its server.
func MCPTools(ctx context.Context, cli client.MCPClient, names []string, maxOutputBytes int) ([]tool.BaseTool, error) {
	tools, err := einomcp.GetTools(ctx, &einomcp.Config{Cli: cli, ToolNameList: names})
	if err != nil {
		return nil, err
	}
	wrapped := make([]tool.BaseTool, 0, len(tools))
	for _, t := range tools {
		invokable, ok := t.(tool.InvokableTool)
		if !ok {
			return nil, fmt.Errorf("MCP tool %q is not invokable", t)
		}
		wrapped = append(wrapped, &cappedTool{InvokableTool: invokable, limit: maxOutputBytes})
	}
	return wrapped, nil
}

type cappedTool struct {
	tool.InvokableTool
	limit int
}

func (t *cappedTool) InvokableRun(ctx context.Context, args string, opts ...tool.Option) (string, error) {
	out, err := t.InvokableTool.InvokableRun(ctx, args, opts...)
	if err != nil {
		return "", err
	}
	if t.limit > 0 && len(out) > t.limit {
		return out[:t.limit] + fmt.Sprintf("\n[output truncated at %d bytes]", t.limit), nil
	}
	return out, nil
}
func JSONToolArguments(value any) (string, error) {
	b, err := json.Marshal(value)
	return string(b), err
}
