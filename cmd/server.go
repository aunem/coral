package cmd

import (
	"github.com/spf13/cobra"
)

// helloCmd represents the hello command
var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "start a coral server",
	Long:  `ascii art goes here`,
}

func init() {
	RootCmd.AddCommand(ServerCmd)
}
