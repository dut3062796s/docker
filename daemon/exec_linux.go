// +build linux

package daemon

import (
	"strings"

	"github.com/docker/docker/daemon/execdriver/lxc"
)

func checkExecSupport(drivername string) error {
	if strings.HasPrefix(drivername, lxc.DriverName) {
		return lxc.ErrExec
	}
	return nil
}
