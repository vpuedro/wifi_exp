package modules

import (
	"github.com/bettercap/bettercap/v2/api"
	"github.com/bettercap/bettercap/v2/modules/wifi"
)

func LoadModules(sess *api.Session) {
	sess.Register(wifi.NewWiFiModule(sess))
}
