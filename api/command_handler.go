package api

import (
	"fmt"
	"regexp"
	"strconv"
	"sync"

	"github.com/bettercap/readline"

	"github.com/evilsocket/islazy/tui"
)

type CommandHandler struct {
	*sync.Mutex
	Name        string
	Description string
	Completer   *readline.PrefixCompleter
	Parser      *regexp.Regexp
	exec        func(args []string, s *Session) error
}

func NewCommandHandler(name string, expr string, desc string, exec func(args []string, s *Session) error) CommandHandler {
	return CommandHandler{
		Mutex:       &sync.Mutex{},
		Name:        name,
		Description: desc,
		Completer:   nil,
		Parser:      regexp.MustCompile(expr),
		exec:        exec,
	}
}

func (h *CommandHandler) Help(padding int) string {
	return fmt.Sprintf("  "+tui.Bold("%"+strconv.Itoa(padding)+"s")+" : %s\n", h.Name, h.Description)
}

func (h *CommandHandler) Parse(line string) (bool, []string) {
	result := h.Parser.FindStringSubmatch(line)
	if len(result) == h.Parser.NumSubexp()+1 {
		return true, result[1:]
	} else {
		return false, nil
	}
}

func (h *CommandHandler) Exec(args []string, s *Session) error {
	h.Lock()
	defer h.Unlock()
	return h.exec(args, s)
}
