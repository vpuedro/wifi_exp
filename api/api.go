package api

// Package api is a minimal command runtime extracted from bettercap's session
// package for the standalone WiFi backend. It keeps only what the wifi module
// needs: module registration, the parameter/environment system, command
// handlers, the event pool and the interactive prompt. Everything session used
// to pull in (caplets, firewall, routing, the JS/otto scripting engine, the
// REST API) has been dropped.

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/bettercap/readline"

	my_log "github.com/bettercap/bettercap/v2/log"
	"github.com/bettercap/bettercap/v2/network"
	"github.com/bettercap/bettercap/v2/packets"

	"github.com/evilsocket/islazy/data"
	"github.com/evilsocket/islazy/fs"
	"github.com/evilsocket/islazy/log"
	"github.com/evilsocket/islazy/str"
	"github.com/evilsocket/islazy/tui"
)

const (
	DefaultHistoryFile = "~/bettercap-wifi.history"
	HistoryEnvVar      = "BETTERCAP_HISTORY"
	AliasesFile        = "~/bettercap-wifi.aliases"
)

var (
	// I is the current (last created) runtime, used by ModuleParam JSON marshaling.
	I *Session

	ErrNotSupported = errors.New("this component is not supported on this OS")

	reCmdSpaceCleaner = regexp.MustCompile(`^([^\s]+)\s+(.+)$`)
	reEnvVarCapture   = regexp.MustCompile(`{env\.([^}]+)}`)

	aliasesFileName, _ = fs.Expand(AliasesFile)
)

func ErrAlreadyStarted(name string) error {
	return fmt.Errorf("module %s is already running", name)
}

func ErrAlreadyStopped(name string) error {
	return fmt.Errorf("module %s is not running", name)
}

type UnknownCommandCallback func(cmd string) bool

// Config holds the few options the standalone WiFi runtime needs.
type Config struct {
	InterfaceName string
	NoColors      bool
	NoHistory     bool
	Debug         bool
	Silent        bool
	EnvFile       string
}

// Session is the minimal runtime that governs the wifi.* commands.
type Session struct {
	Config    Config
	Interface *network.Endpoint
	Gateway   *network.Endpoint
	Env       *Environment
	WiFi      *network.WiFi
	Queue     *packets.Queue
	StartedAt time.Time
	Active    bool

	Modules          ModuleList
	Aliases          *data.UnsortedKV
	Input            *readline.Instance
	Prompt           Prompt
	CoreHandlers     []CommandHandler
	Events           *EventPool
	EventsIgnoreList *EventsIgnoreList
	UnkCmdCallback   UnknownCommandCallback
}

// New builds the runtime. Register modules on it, then call Start.
func New(cfg Config) (*Session, error) {
	if cfg.NoColors || !tui.Effects() {
		tui.Disable()
		log.NoEffects = true
	}

	s := &Session{
		Config:           cfg,
		Prompt:           NewPrompt(),
		Active:           false,
		Modules:          make(ModuleList, 0),
		CoreHandlers:     make([]CommandHandler, 0),
		EventsIgnoreList: NewEventsIgnoreList(),
	}

	var err error
	if s.Env, err = NewEnvironment(cfg.EnvFile); err != nil {
		return nil, err
	}

	if s.Aliases, err = data.NewUnsortedKV(aliasesFileName, data.FlushOnEdit); err != nil {
		return nil, err
	}

	s.Events = NewEventPool(cfg.Debug, cfg.Silent)

	s.registerCoreHandlers()

	if I == nil {
		I = s
		my_log.Logger = s.Events.Log
	}

	return s, nil
}

// Start finds the interface, wires the WiFi/LAN state, the packet queue and the
// interactive prompt. No gateway/routing detection is performed: monitor-mode
// WiFi does not need it.
func (s *Session) Start() error {
	var err error

	network.Debug = func(format string, args ...interface{}) {
		s.Events.Log(log.DEBUG, format, args...)
	}

	// keep modules sorted by name
	sort.Slice(s.Modules, func(i, j int) bool {
		return s.Modules[i].Name() < s.Modules[j].Name()
	})

	if s.Interface, err = network.FindInterface(s.Config.InterfaceName); err != nil {
		return err
	}

	if s.Queue, err = packets.NewQueue(s.Interface); err != nil {
		return err
	}

	// no routing in the wifi-only build: we are our own gateway
	s.Gateway = s.Interface

	s.WiFi = network.NewWiFi(s.Interface, s.Aliases, func(ap *network.AccessPoint) {
		s.Events.Add("wifi.ap.new", ap)
	}, func(ap *network.AccessPoint) {
		s.Events.Add("wifi.ap.lost", ap)
	})

	s.setupEnv()

	// the prompt/readline is best-effort: when there is no TTY (the runtime is
	// driven purely through Run) we keep going without an interactive input.
	if err := s.setupReadline(); err != nil {
		s.Events.Log(log.DEBUG, "readline unavailable: %v", err)
		s.Input = nil
	}

	s.setupSignals()

	s.StartedAt = time.Now()
	s.Active = true

	s.startNetMon()

	s.Events.Add("session.started", nil)

	return nil
}

func (s *Session) Close() {
	if s.Config.Debug {
		s.Events.Add("session.closing", nil)
	}

	for _, m := range s.Modules {
		if m.Running() {
			m.Stop()
		}
	}

	if s.Config.EnvFile != "" {
		envFile, _ := fs.Expand(s.Config.EnvFile)
		if err := s.Env.Save(envFile); err != nil {
			fmt.Printf("error while storing the environment to %s: %s\n", envFile, err)
		}
	}
}

func (s *Session) Register(mod Module) error {
	s.Modules = append(s.Modules, mod)
	return nil
}

func (s *Session) Module(name string) (error, Module) {
	for _, m := range s.Modules {
		if m.Name() == name {
			return nil, m
		}
	}
	return fmt.Errorf("module %s not found", name), nil
}

func (s *Session) IsOn(moduleName string) bool {
	for _, m := range s.Modules {
		if m.Name() == moduleName {
			return m.Running()
		}
	}
	return false
}

func (s *Session) Refresh() {
	if s.Input == nil {
		return
	}
	p, _ := s.parseEnvTokens(s.Prompt.Render(s))
	s.Input.SetPrompt(p)
	s.Input.Refresh()
}

func (s *Session) ReadLine() (string, error) {
	if s.Input == nil {
		return "", errors.New("no interactive input available")
	}
	s.Refresh()
	return s.Input.Readline()
}

// Run parses and executes a single command line (a core command or a module
// command such as "wifi.recon on").
func (s *Session) Run(line string) error {
	line = str.TrimRight(line)
	line = reCmdSpaceCleaner.ReplaceAllString(line, "$1 $2")

	line, err := s.parseEnvTokens(line)
	if err != nil {
		return err
	}

	// core command?
	for _, h := range s.CoreHandlers {
		if parsed, args := h.Parse(line); parsed {
			return h.Exec(args, s)
		}
	}

	// module command?
	for _, mod := range s.Modules {
		for _, modHandler := range mod.Handlers() {
			if parsed, args := modHandler.Parse(line); parsed {
				if err := modHandler.Exec(args); err != nil {
					return err
				} else if prompt := mod.Prompt(); prompt != "" {
					s.Env.Set(PromptVariable, prompt)
					s.Refresh()
				}
				return nil
			}
		}
	}

	if s.UnkCmdCallback != nil && s.UnkCmdCallback(line) {
		return nil
	}

	return fmt.Errorf("unknown or invalid syntax \"%s%s%s\", type %shelp%s for the help menu", tui.BOLD, line, tui.RESET, tui.BOLD, tui.RESET)
}

func (s *Session) registerCoreHandlers() {
	s.CoreHandlers = append(s.CoreHandlers, NewCommandHandler("help",
		`^(help|\?)$`,
		"Display list of available commands.",
		func(args []string, s *Session) error {
			s.helpCommand()
			return nil
		}))

	s.CoreHandlers = append(s.CoreHandlers, NewCommandHandler("quit",
		`^(q|quit|exit|e)$`,
		"Close the session and exit.",
		func(args []string, s *Session) error {
			s.Active = false
			return nil
		}))

	s.CoreHandlers = append(s.CoreHandlers, NewCommandHandler("get",
		`^get\s+(.+)$`,
		"Get the value of variable NAME ('*' for all).",
		func(args []string, s *Session) error {
			s.getCommand(str.Trim(args[0]))
			return nil
		}))

	s.CoreHandlers = append(s.CoreHandlers, NewCommandHandler("set",
		`^set\s+([^\s]+)\s+(.+)$`,
		"Set the VALUE of variable NAME.",
		func(args []string, s *Session) error {
			s.Env.Set(args[0], args[1])
			return nil
		}))

	s.CoreHandlers = append(s.CoreHandlers, NewCommandHandler("clear",
		`^(clear|cls)$`,
		"Clear the screen.",
		func(args []string, s *Session) error {
			fmt.Print("\033[2J\033[H")
			return nil
		}))
}

func (s *Session) getCommand(what string) {
	if what == "*" {
		for _, name := range s.Env.Sorted() {
			_, v := s.Env.Get(name)
			fmt.Printf("  %s : %s\n", tui.Yellow(name), v)
		}
		return
	}
	if found, v := s.Env.Get(what); found {
		fmt.Printf("  %s : %s\n", tui.Yellow(what), v)
	} else {
		fmt.Printf("  %s is not defined\n", tui.Yellow(what))
	}
}

func (s *Session) helpCommand() {
	fmt.Println()
	fmt.Println(tui.Bold("Core commands:"))
	for _, h := range s.CoreHandlers {
		fmt.Print(h.Help(20))
	}
	for _, m := range s.Modules {
		fmt.Printf("\n%s ( %s )\n", tui.Bold(m.Name()), m.Description())
		for _, h := range m.Handlers() {
			fmt.Print(h.Help(20))
		}
	}
	fmt.Println()
}

func (s *Session) setupEnv() {
	s.Env.Set("iface.index", fmt.Sprintf("%d", s.Interface.Index))
	s.Env.Set("iface.name", s.Interface.Name())
	s.Env.Set("iface.ipv4", s.Interface.IpAddress)
	s.Env.Set("iface.ipv6", s.Interface.Ip6Address)
	s.Env.Set("iface.mac", s.Interface.HwAddress)
	s.Env.Set("gateway.address", s.Gateway.IpAddress)
	s.Env.Set("gateway.mac", s.Gateway.HwAddress)

	if found, v := s.Env.Get(PromptVariable); !found || v == "" {
		if s.Interface.IsMonitor() {
			s.Env.Set(PromptVariable, DefaultPromptMonitor)
		} else {
			s.Env.Set(PromptVariable, DefaultPrompt)
		}
	}

	dbg := "false"
	if s.Config.Debug {
		dbg = "true"
	}
	s.Env.WithCallback("log.debug", dbg, func(newValue string) {
		s.Events.SetDebug(newValue == "true")
	})

	silent := "false"
	if s.Config.Silent {
		silent = "true"
	}
	s.Env.WithCallback("log.silent", silent, func(newValue string) {
		s.Events.SetSilent(newValue == "true")
	})
}

func containsCapitals(s string) bool {
	for _, ch := range s {
		if ch < 133 && ch > 101 {
			return false
		}
	}
	return true
}

func (s *Session) setupReadline() (err error) {
	prefixCompleters := make([]readline.PrefixCompleterInterface, 0)
	for _, h := range s.CoreHandlers {
		if h.Completer == nil {
			prefixCompleters = append(prefixCompleters, readline.PcItem(h.Name))
		} else {
			prefixCompleters = append(prefixCompleters, h.Completer)
		}
	}

	tree := make(map[string][]string)
	for _, m := range s.Modules {
		for _, h := range m.Handlers() {
			if h.Completer == nil {
				parts := strings.Split(h.Name, " ")
				name := parts[0]

				if _, found := tree[name]; !found {
					tree[name] = []string{}
				}

				appendedOption := strings.Join(parts[1:], " ")
				if len(appendedOption) > 0 && !containsCapitals(appendedOption) {
					tree[name] = append(tree[name], appendedOption)
				}
			} else {
				prefixCompleters = append(prefixCompleters, h.Completer)
			}
		}
	}

	for root, subElems := range tree {
		item := readline.PcItem(root)
		item.Children = []readline.PrefixCompleterInterface{}
		for _, child := range subElems {
			item.Children = append(item.Children, readline.PcItem(child))
		}
		prefixCompleters = append(prefixCompleters, item)
	}

	history := ""
	if !s.Config.NoHistory {
		histPath := DefaultHistoryFile
		if fromEnv := os.Getenv(HistoryEnvVar); fromEnv != "" {
			histPath = fromEnv
		}
		history, _ = fs.Expand(histPath)
	}

	cfg := readline.Config{
		HistoryFile:     history,
		InterruptPrompt: "^C",
		EOFPrompt:       "^D",
		AutoComplete:    readline.NewPrefixCompleter(prefixCompleters...),
	}

	s.Input, err = readline.NewEx(&cfg)
	return err
}

func (s *Session) startNetMon() {
	// drain queue activities so packet senders never block; there is no
	// net.recon module in the wifi-only build to consume them.
	go func() {
		for range s.Queue.Activities {
			if !s.Active {
				return
			}
		}
	}()
}

func (s *Session) setupSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println()
		s.Events.Log(log.WARNING, "Got SIGTERM")
		s.Close()
		os.Exit(0)
	}()
}
