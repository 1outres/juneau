package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/1outres/juneau/daemon/internal/cni"
	"github.com/1outres/juneau/daemon/pkg/juneaupb"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
)

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Del:   cmdDel,
		Check: cmdCheck,
	}, version.All, "")
}

func cmdAdd(args *skel.CmdArgs) error {
	return executeCmd(args, func(cni *cni.Cni) CmdFunc {
		return cni.CmdAdd
	})
}

func cmdDel(args *skel.CmdArgs) error {
	return executeCmd(args, func(cni *cni.Cni) CmdFunc {
		return cni.CmdDel
	})
}

func cmdCheck(args *skel.CmdArgs) error {
	return executeCmd(args, func(cni *cni.Cni) CmdFunc {
		return cni.CmdCheck
	})
}

type NetConf struct {
	types.NetConf
}

type CmdFunc func(context.Context) error

func executeCmd(args *skel.CmdArgs, cmd func(cni *cni.Cni) CmdFunc) error {
	logFile, err := os.OpenFile("/var/log/juneau-cni.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return &types.Error{
			Code:    types.ErrInternal,
			Msg:     "Failed to open log file",
			Details: err.Error(),
		}
	}
	defer logFile.Close()

	writeSyncer := zapcore.AddSync(logFile)
	encoderCfg := zap.NewDevelopmentEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		writeSyncer,
		zap.DebugLevel,
	)

	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	grpcConn, err := grpc.Dial(
		"unix:///var/run/juneaud.sock",
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	)
	if err != nil {
		zap.L().Error("Failed to connect to juneaud", zap.Error(err))
		return &types.Error{
			Code:    types.ErrInternal,
			Msg:     "Failed to connect to juneaud",
			Details: err.Error(),
		}
	}

	ipamClient := juneaupb.NewIPAMClient(grpcConn)

	parsedArgs := parseCNIArgs(args.Args)
	zap.L().Debug("Cmd executed", zap.Any("args", parsedArgs))

	podNamespace := parsedArgs["K8S_POD_NAMESPACE"]
	podName := parsedArgs["K8S_POD_NAME"]
	podUID := parsedArgs["K8S_POD_UID"]

	zap.ReplaceGlobals(zap.L().With(zap.String("pod", podNamespace+"/"+podName)))

	var netConf *NetConf
	if err := json.Unmarshal(args.StdinData, &netConf); err != nil {
		zap.L().Error("Failed to decode CNI config", zap.Error(err))
		return &types.Error{
			Code:    types.ErrDecodingFailure,
			Msg:     "Failed to decode CNI config",
			Details: err.Error(),
		}
	}

	cni := &cni.Cni{
		IPAMClient: ipamClient,

		PodNamespace: podNamespace,
		PodName:      podName,
		PodUID:       podUID,
		ContainerID:  args.ContainerID,
		Netns:        args.Netns,
		IfName:       args.IfName,

		CNIVersion: netConf.CNIVersion,
	}

	ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute)
	defer ctxCancel()

	zap.L().Info("CNI Initialized")

	return cmd(cni)(ctx)
}

func parseCNIArgs(argStr string) map[string]string {
	kvs := make(map[string]string)
	for _, pair := range strings.Split(argStr, ";") {
		if parts := strings.SplitN(pair, "=", 2); len(parts) == 2 {
			kvs[parts[0]] = parts[1]
		}
	}
	return kvs
}
