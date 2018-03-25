package cmd

import (
	"flag"

	"github.com/golang/glog"
	"github.com/spf13/cobra"
)

// grpcCmd represents the hello command
var grpcCmd = &cobra.Command{
	Use:   "grpc",
	Short: "start a grpc server",
	Long:  `ascii art goes here`,
	Run:   GRPCServer,
}

func init() {
	ServerCmd.AddCommand(grpcCmd)
}

// Implements of EchoServiceServer

func Run() error {
	// listen, err := net.Listen("tcp", ":50051")
	// if err != nil {
	// 	return err
	// }
	// server := grpc.NewServer()
	// pb.RegisterEchoServiceServer(server, newEchoServer())
	// server.Serve(listen)
	return nil
}

func GRPCServer(cmd *cobra.Command, args []string) {
	flag.Parse()
	defer glog.Flush()

	if err := Run(); err != nil {
		glog.Fatal(err)
	}
}
