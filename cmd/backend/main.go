package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kayden-vs/sentinel-proxy/internal/config"
	pb "github.com/kayden-vs/sentinel-proxy/proto/sentinel"
)

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.Logging.Level),
	}))
	slog.SetDefault(logger)

	lis, err := net.Listen("tcp", cfg.Backend.ListenAddr)
	if err != nil {
		logger.Error("failed to listen", "addr", cfg.Backend.ListenAddr, "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer(
		grpc.MaxSendMsgSize(cfg.Backend.MaxSendMsgSize),
	)

	svc := &dataServiceServer{
		cfg:    cfg,
		logger: logger,
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	pb.RegisterDataServiceServer(grpcServer, svc)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("received shutdown signal", "signal", sig)
		grpcServer.GracefulStop()
	}()

	logger.Info("backend gRPC server starting",
		"addr", cfg.Backend.ListenAddr,
		"latency", cfg.Backend.SimulatedLatency,
	)

	if err := grpcServer.Serve(lis); err != nil {
		logger.Error("gRPC server failed", "error", err)
		os.Exit(1)
	}
}
