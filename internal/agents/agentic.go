package agents

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/log"
)

const (
	defaultAgenticIterations = 6
	defaultAgenticToolCalls  = 16
	maxTrajectoryChars       = 60000
)

type agenticRun struct {
	Content      string
	Messages     []clients.Message
	InputTokens  int32
	OutputTokens int32
	ToolCalls    int
}

func (agent *DetectionAgent) runAgentic(ctx context.Context, client clients.LLMClient, phase, system, user string,
	options *clients.GenerateOptions) (*agenticRun, error) {
	toolClient, ok := client.(clients.ToolCallingClient)
	if !ok {
		return nil, fmt.Errorf("%s model does not support tool calling", phase)
	}
	if agent.sandbox == nil {
		return nil, fmt.Errorf("agentic sandbox is unavailable")
	}
	iterations, calls := agent.agenticBudgets()
	system += "\n\nYou are operating as an agentic " + phase + " phase. Before reaching a conclusion, you MUST call at least one read-only repository tool. Use search_code, read_file, or list_directory to inspect evidence that is not fully established by the supplied file. Do not provide the final JSON result until a tool result has been returned."
	run := &agenticRun{Messages: []clients.Message{{Role: "system", Content: system}, {Role: "user", Content: user}}}
	for turn := 0; turn < iterations; turn++ {
		response, err := toolClient.GenerateWithTools(ctx, run.Messages, agenttools.Definitions(), options)
		if err != nil {
			return nil, err
		}
		run.InputTokens += response.InputTokens
		run.OutputTokens += response.OutputTokens
		run.Messages = append(run.Messages, clients.Message{Role: "assistant", Content: response.Content, ToolCalls: response.ToolCalls})
		if len(response.ToolCalls) == 0 {
			break
		}
		for _, call := range response.ToolCalls {
			if run.ToolCalls >= calls {
				break
			}
			output := agenttools.Execute(agent.sandbox, call.Name, call.Arguments)
			if len(output)+trajectorySize(run.Messages) > maxTrajectoryChars {
				return nil, fmt.Errorf("%s tool output budget exhausted", phase)
			}
			run.Messages = append(run.Messages, clients.Message{Role: "tool", ToolCallID: call.ID, Content: output})
			run.ToolCalls++
		}
		if run.ToolCalls >= calls {
			break
		}
	}
	if run.ToolCalls == 0 {
		return nil, fmt.Errorf("%s completed without using a repository tool", phase)
	}
	run.Messages = append(run.Messages, clients.Message{Role: "user", Content: "Use the repository evidence above and return only the requested JSON result now."})
	response, err := toolClient.GenerateWithTools(ctx, run.Messages, nil, options)
	if err != nil {
		return nil, err
	}
	run.InputTokens += response.InputTokens
	run.OutputTokens += response.OutputTokens
	run.Content = response.Content
	log.FromContext(ctx).Infof("agentic %s completed tools=%d input_tokens=%d output_tokens=%d", phase, run.ToolCalls, run.InputTokens, run.OutputTokens)
	return run, nil
}

func (agent *DetectionAgent) agenticBudgets() (int, int) {
	iterations, calls := agent.agentOption.AgenticMaxIterations, agent.agentOption.AgenticMaxToolCalls
	if iterations <= 0 {
		iterations = defaultAgenticIterations
	}
	if calls <= 0 {
		calls = defaultAgenticToolCalls
	}
	return iterations, calls
}

func trajectorySize(messages []clients.Message) int {
	total := 0
	for _, message := range messages {
		total += len(message.Content) + len(message.ToolCallID)
		for _, call := range message.ToolCalls {
			total += len(call.ID) + len(call.Name) + len(call.Arguments)
		}
	}
	return total
}

func (run *agenticRun) trajectory() string {
	var builder strings.Builder
	for _, message := range run.Messages {
		builder.WriteString("[" + message.Role + "]\n")
		builder.WriteString(message.Content)
		builder.WriteString("\n")
		for _, call := range message.ToolCalls {
			builder.WriteString("tool " + call.Name + " " + call.Arguments + "\n")
		}
		if builder.Len() >= maxTrajectoryChars {
			break
		}
	}
	value := builder.String()
	if len(value) > maxTrajectoryChars {
		return value[len(value)-maxTrajectoryChars:]
	}
	return value
}
