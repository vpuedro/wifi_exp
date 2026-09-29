package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/bettercap/bettercap/v2/api"
	"github.com/bettercap/bettercap/v2/core"
	"github.com/bettercap/bettercap/v2/httpd"
	"github.com/bettercap/bettercap/v2/log"
	"github.com/bettercap/bettercap/v2/modules"

	"github.com/evilsocket/islazy/str"
	"github.com/evilsocket/islazy/tui"
)

var (
	iface        = flag.String("iface", "", "Network interface to bind to, leave empty for autodetection.")
	eval         = flag.String("eval", "", "Run one or more commands separated by ; before serving, used to set variables/options.")
	envFile      = flag.String("env-file", "", "Load and persist environment variables from this file.")
	apiAddress   = flag.String("api-address", "127.0.0.1:8081", "Address:port the HTTP API listens on (empty to disable).")
	apiToken     = flag.String("api-token", "", "If set, every HTTP API request must carry it in the X-Api-Token header.")
	interactive  = flag.Bool("interactive", false, "Also run the interactive command prompt on stdin.")
	noColors     = flag.Bool("no-colors", false, "Disable output color effects.")
	noHistory    = flag.Bool("no-history", false, "Disable interactive session history file.")
	debug        = flag.Bool("debug", false, "Print debug messages.")
	silent       = flag.Bool("silent", false, "Suppress all logs which are not errors.")
	printVersion = flag.Bool("version", false, "Print the version and exit.")
)

func main() {
	flag.Parse()

	if *printVersion {
		fmt.Printf("%s-wifi v%s (built for %s %s with %s)\n", core.Name, core.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	sess, err := api.New(api.Config{
		InterfaceName: *iface,
		NoColors:      *noColors,
		NoHistory:     *noHistory,
		Debug:         *debug,
		Silent:        *silent,
		EnvFile:       *envFile,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer sess.Close()

	appName := fmt.Sprintf("%s-wifi v%s", core.Name, core.Version)
	appBuild := fmt.Sprintf("(built for %s %s with %s)", runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Printf("%s %s\n\n", tui.Bold(appName), tui.Dim(appBuild))

	// only the WiFi module is registered
	modules.LoadModules(sess)

	if err = sess.Start(); err != nil {
		log.Fatal("%s", err)
	}

	// commands passed with -eval run first (e.g. to set variables/options)
	for _, cmd := range parseCommands(*eval) {
		if err = sess.Run(cmd); err != nil {
			log.Error("error while running '%s': %s", tui.Bold(cmd), tui.Red(err.Error()))
		}
	}

	// start the HTTP API
	if *apiAddress != "" {
		server := httpd.New(sess, *apiAddress, *apiToken)
		fmt.Printf("HTTP API listening on %s\n", tui.Bold("http://"+*apiAddress))
		go func() {
			if err := server.ListenAndServe(); err != nil {
				log.Fatal("http api: %s", err)
			}
		}()
		defer server.Close()
	}

	if *interactive {
		runREPL(sess)
	} else if *apiAddress != "" {
		// serve until a signal closes the session
		select {}
	}
}

func runREPL(sess *api.Session) {
	fmt.Printf("Type '%s' for a list of commands.\n\n", tui.Bold("help"))
	for sess.Active {
		line, err := sess.ReadLine()
		if err != nil {
			if err == io.EOF || err.Error() == "Interrupt" {
				sess.Run("exit")
				break
			}
			log.Fatal("%s", err)
		}
		for _, cmd := range parseCommands(line) {
			if err = sess.Run(cmd); err != nil {
				log.Error("%s", err)
			}
		}
	}
}

func parseCommands(line string) []string {
	out := make([]string, 0)
	for _, cmd := range strings.Split(line, ";") {
		if cmd = str.Trim(cmd); cmd != "" {
			out = append(out, cmd)
		}
	}
	return out
}
