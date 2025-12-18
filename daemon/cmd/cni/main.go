package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/1outres/juneau/daemon/pkg/cnipb"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/create"
	"github.com/containernetworking/cni/pkg/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/status"
)

type NetConf struct {
	types.NetConf
	Daemon DaemonConf `json:"daemon"`
}

type DaemonConf struct {
	Socket    string `json:"socket"`
	TimeoutMs int    `json:"timeoutMs"`
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Del:   cmdDel,
		Check: cmdCheck,
	}, version.All, "")
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	conn, err := connect(conf.Daemon.Socket)
	if err != nil {
		return err
	}
	client := cnipb.NewCNIClient(conn)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(conf.Daemon.TimeoutMs)*time.Millisecond)
	defer cancel()

	req := makeCNIRequest(args)
	resp, err := client.Add(ctx, req)
	if err != nil {
		return convertError(err)
	}

	if resp == nil {
		return types.NewError(types.ErrInternal, "daemon returned empty response", "")
	}

	result, err := create.CreateFromBytes(resp.GetResultJson())
	if err != nil {
		return types.NewError(types.ErrDecodingFailure, "failed to decode daemon result", err.Error())
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	conn, err := connect(conf.Daemon.Socket)
	if err != nil {
		return err
	}
	client := cnipb.NewCNIClient(conn)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(conf.Daemon.TimeoutMs)*time.Millisecond)
	defer cancel()

	req := makeCNIRequest(args)
	if _, err := client.Del(ctx, req); err != nil {
		return convertError(err)
	}

	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	conn, err := connect(conf.Daemon.Socket)
	if err != nil {
		return err
	}
	client := cnipb.NewCNIClient(conn)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(conf.Daemon.TimeoutMs)*time.Millisecond)
	defer cancel()

	req := makeCNIRequest(args)
	if _, err := client.Check(ctx, req); err != nil {
		return convertError(err)
	}

	return nil
}

func parseConfig(data []byte) (*NetConf, error) {
	conf := &NetConf{}

	if err := json.Unmarshal(data, conf); err != nil {
		return nil, fmt.Errorf("failed to parse CNI config: %w", err)
	}

	return conf, nil
}

func parseArgs(argStr string) map[string]string {
	kvs := make(map[string]string)
	for pair := range strings.SplitSeq(argStr, ";") {
		if parts := strings.SplitN(pair, "=", 2); len(parts) == 2 {
			kvs[parts[0]] = parts[1]
		}
	}
	return kvs
}

func makeCNIRequest(args *skel.CmdArgs) *cnipb.CNIRequest {
	return &cnipb.CNIRequest{
		ContainerId: args.ContainerID,
		Netns:       args.Netns,
		Ifname:      args.IfName,
		Path:        args.Path,
		Args:        parseArgs(args.Args),
		StdinData:   args.StdinData,
	}
}

func connect(sock string) (*grpc.ClientConn, error) {
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.Dial("unix", addr)
	}
	resolver.SetDefaultScheme("passthrough")

	conn, err := grpc.NewClient(
		sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		return nil, types.NewError(types.ErrTryAgainLater, "failed to connect to daemon socket "+sock, err.Error())
	}
	return conn, nil
}

func convertError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return types.NewError(types.ErrInternal, "failed to talk with daemon", err.Error())
	}

	for _, d := range st.Details() {
		if cniErr, ok := d.(*cnipb.CNIError); ok {
			return types.NewError(uint(cniErr.GetCode()), cniErr.GetMsg(), cniErr.GetDetails())
		}
	}

	return types.NewError(types.ErrInternal, st.Message(), st.Code().String())
}
