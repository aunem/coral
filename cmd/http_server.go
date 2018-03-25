package cmd

import (
	"flag"
	"net/http"

	"github.com/golang/glog"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	pb "github.com/kubecorp/coral/api"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	endpoint string
)

var httpCmd = &cobra.Command{
	Use:   "http",
	Short: "start a http server",
	Long:  `ascii art goes here`,
	Run:   HTTPServer,
}

func init() {
	ServerCmd.AddCommand(httpCmd)
	httpCmd.Flags().StringVarP(&endpoint, "endpoint", "e", "localhost:50051", "endpoint for coral service")
}

func RunEndPoint(address string, opts ...runtime.ServeMuxOption) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux(opts...)
	dialOpts := []grpc.DialOption{grpc.WithInsecure()}
	err := pb.RegisterCoralHandlerFromEndpoint(ctx, mux, endpoint, dialOpts)
	if err != nil {
		return err
	}

	http.ListenAndServe(address, mux)
	return nil
}

func HTTPServer(cmd *cobra.Command, args []string) {
	flag.Parse()
	defer glog.Flush()

	if err := RunEndPoint(":8080"); err != nil {
		glog.Fatal(err)
	}
}
