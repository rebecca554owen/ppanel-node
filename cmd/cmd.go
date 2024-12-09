package cmd

import (
	log "github.com/sirupsen/logrus"

	_ "github.com/perfect-panel/ppanel-node/core/imports"
	"github.com/spf13/cobra"
)

var command = &cobra.Command{
	Use: "ppnode",
}

func Run() {
	err := command.Execute()
	if err != nil {
		log.WithField("err", err).Error("Execute command failed")
	}
}
