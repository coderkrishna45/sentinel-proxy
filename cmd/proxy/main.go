package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kayden-vs/sentinel-proxy/internal/config"
	"github.com/kayden-vs/sentinel-proxy/internal/identity"
	"github.com/kayden-vs/sentinel-proxy/internal/metrics"
	"github.com/kayden-vs/sentinel-proxy/internal/policy"
	redisclient "github.com/kayden-vs/sentinel-proxy/internal/redis"
	"github.com/kayden-vs/sentinel-proxy/internal/stream"
	"github.com/kayden-vs/sentinel-proxy/internal/threshold"
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

	logger.Info("sentinel-proxy starting", "config", cfg.String())

	p, err := newProxy(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize proxy", "error", err)
		os.Exit(1)
	}
	defer p.close()

	mux := http.NewServeMux()
	mux.HandleFunc("/data", p.handleData)
	mux.HandleFunc("/export", p.handleExport)
	mux.HandleFunc("/health", p.handleHealth)
	mux.HandleFunc("/simulate/normal", p.handleSimulateNormal)
	mux.HandleFunc("/simulate/attack", p.handleSimulateAttack)
	mux.HandleFunc("/simulate/export", p.handleSimulateExport)

	handler := p.concurrencyMiddleware(p.loggingMiddleware(mux))

	server := &http.Server{
		Addr:         cfg.Proxy.ListenAddr,
		Handler:      handler,
		ReadTimeout:  cfg.Proxy.ReadTimeout,
		WriteTimeout: cfg.Proxy.WriteTimeout,
		IdleTimeout:  cfg.Proxy.IdleTimeout,
	}

	var metricsServer *http.Server
	if cfg.Metrics.Enabled {
		metricsMux := http.NewServeMux()
		metricsMux.Handle(cfg.Metrics.Path, metrics.Handler())
		metricsServer = &http.Server{
			Addr:    cfg.Metrics.ListenAddr,
			Handler: metricsMux,
		}
		go func() {
			logger.Info("metrics server starting", "addr", cfg.Metrics.ListenAddr, "path", cfg.Metrics.Path)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("metrics server failed", "error", err)
			}
		}()
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("received shutdown signal", "signal", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if metricsServer != nil {
			metricsServer.Shutdown(ctx)
		}
		server.Shutdown(ctx)
	}()

	logger.Info("sentinel-proxy listening",
		"addr", cfg.Proxy.ListenAddr,
		"backend", cfg.Proxy.BackendAddr,
	)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("proxy server failed", "error", err)
		os.Exit(1)
	}

	logger.Info("sentinel-proxy shutdown complete")
}

type proxyServer struct {
	cfg        *config.Config
	logger     *slog.Logger
	resolver   *identity.Resolver
	redis      *redisclient.FailOpenClient
	engine     *threshold.Engine
	enforcer   *policy.Enforcer
	grpcConn   *grpc.ClientConn
	grpcClient pb.DataServiceClient
	m          *metrics.Metrics
	sem        chan struct{}
	activeReq  sync.WaitGroup
}

func newProxy(cfg *config.Config, logger *slog.Logger) (*proxyServer, error) {
	rc := redisclient.NewFailOpenClient(cfg.Redis, func(err error) {
		logger.Error("REDIS CRITICAL ALERT: Redis unavailable, operating in fail-open mode",
			"error", err,
		)
		metrics.Get().RedisErrors.Inc()
	})

	if rc.IsAvailable() {
		logger.Info("redis connection established", "addr", cfg.Redis.Addr)
	} else {
		logger.Warn("redis unavailable, operating in fail-open mode", "addr", cfg.Redis.Addr)
	}

	grpcConn, err := grpc.NewClient(
		cfg.Proxy.BackendAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(cfg.Backend.MaxSendMsgSize),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to gRPC backend: %w", err)
	}

	grpcClient := pb.NewDataServiceClient(grpcConn)

	return &proxyServer{
		cfg:        cfg,
		logger:     logger,
		resolver:   identity.NewResolver(cfg.Proxy.JWTSecret),
		redis:      rc,
		engine:     threshold.NewEngine(cfg.Threshold),
		enforcer:   policy.NewEnforcer(rc, cfg.Policies.GraceViolations),
		grpcConn:   grpcConn,
		grpcClient: grpcClient,
		m:          metrics.Get(),
		sem:        make(chan struct{}, cfg.Proxy.MaxConcurrent),
	}, nil
}

func (p *proxyServer) close() {
	p.activeReq.Wait()
	if p.grpcConn != nil {
		p.grpcConn.Close()
	}
	p.redis.Close()
}

func (p *proxyServer) handleData(w http.ResponseWriter, r *http.Request) {
	p.handleStream(w, r, "/data", pb.DataMode_DATA_MODE_NORMAL)
}

func (p *proxyServer) handleExport(w http.ResponseWriter, r *http.Request) {
	p.handleStream(w, r, "/export", pb.DataMode_DATA_MODE_EXPORT)
}

func (p *proxyServer) handleSimulateNormal(w http.ResponseWriter, r *http.Request) {
	p.handleStream(w, r, "/data", pb.DataMode_DATA_MODE_NORMAL)
}

func (p *proxyServer) handleSimulateAttack(w http.ResponseWriter, r *http.Request) {
	p.handleStream(w, r, "/data", pb.DataMode_DATA_MODE_ATTACK)
}

func (p *proxyServer) handleSimulateExport(w http.ResponseWriter, r *http.Request) {
	p.handleStream(w, r, "/export", pb.DataMode_DATA_MODE_EXPORT)
}

func (p *proxyServer) handleStream(w http.ResponseWriter, r *http.Request, endpoint string, mode pb.DataMode) {
	startTime := time.Now()

	ident := p.resolver.Resolve(r)
	p.m.IdentityResolutions.WithLabelValues(ident.Method).Inc()

	p.logger.Info("request received",
		"user_id", ident.UserID,
		"method", ident.Method,
		"role", ident.Role,
		"endpoint", endpoint,
		"mode", mode.String(),
		"remote_addr", r.RemoteAddr,
	)

	if policy.IsBypassed(
		p.cfg.Proxy.BypassHeader,
		p.cfg.Proxy.BypassSecret,
		r.Header.Get(p.cfg.Proxy.BypassHeader),
	) {
		p.logger.Warn("bypass header detected, skipping enforcement",
			"user_id", ident.UserID,
			"endpoint", endpoint,
		)
		p.streamWithoutEnforcement(w, r, ident, endpoint, mode)
		return
	}

	ctx := r.Context()
	stats, err := p.redis.GetBehaviorStats(ctx, ident.UserID)
	if err != nil {
		p.logger.Error("failed to get behavior stats (fail-open)",
			"user_id", ident.UserID,
			"error", err,
		)
	}

	decision := p.engine.Evaluate(stats, endpoint, ident.Role, p.cfg.Policies, 0)

	p.logger.Info("threshold decision",
		"user_id", ident.UserID,
		"allowed", decision.Allowed,
		"ceiling", decision.AbsoluteCeiling,
		"floor", decision.GlobalFloor,
		"historical_avg", decision.HistoricalAvg,
		"is_new_user", decision.IsNewUser,
		"explanation", decision.Explanation,
	)

	grpcCtx, grpcCancel := context.WithCancel(ctx)
	defer grpcCancel()

	grpcReq := &pb.DataRequest{
		UserId:   ident.UserID,
		Endpoint: endpoint,
		Mode:     mode,
	}

	grpcStream, err := p.grpcClient.GetData(grpcCtx, grpcReq)
	if err != nil {
		p.logger.Error("failed to open gRPC stream",
			"user_id", ident.UserID,
			"error", err,
		)
		http.Error(w, `{"error": "backend unavailable"}`, http.StatusBadGateway)
		p.m.RequestsTotal.WithLabelValues(endpoint, "502", ident.Method).Inc()
		return
	}

	monitor := stream.NewMonitor(stream.MonitorConfig{
		UserID:   ident.UserID,
		Endpoint: endpoint,
		Role:     ident.Role,
		Decision: decision,
		Engine:   p.engine,
		Enforcer: p.enforcer,
		Redis:    p.redis,
		Config:   *p.cfg,
		Logger:   p.logger,
		Cancel:   grpcCancel,
	})

	result := monitor.Stream(ctx, grpcStream, w)

	statusCode := "200"
	if result.Killed {
		statusCode = "429"
	}

	p.m.RequestsTotal.WithLabelValues(endpoint, statusCode, ident.Method).Inc()

	p.logger.Info("request completed",
		"user_id", ident.UserID,
		"endpoint", endpoint,
		"total_bytes", result.TotalBytes,
		"chunks", result.ChunkCount,
		"duration", result.Duration,
		"outcome", result.Outcome,
		"killed", result.Killed,
		"kill_reason", result.KillReason,
		"throttled", result.Throttled,
		"latency", time.Since(startTime),
	)
}

func (p *proxyServer) streamWithoutEnforcement(w http.ResponseWriter, r *http.Request, ident *identity.Info, endpoint string, mode pb.DataMode) {
	ctx := r.Context()
	grpcCtx, grpcCancel := context.WithCancel(ctx)
	defer grpcCancel()

	grpcReq := &pb.DataRequest{
		UserId:   ident.UserID,
		Endpoint: endpoint,
		Mode:     mode,
	}

	grpcStream, err := p.grpcClient.GetData(grpcCtx, grpcReq)
	if err != nil {
		http.Error(w, `{"error": "backend unavailable"}`, http.StatusBadGateway)
		return
	}

	noEnforcementDecision := &threshold.Decision{
		Allowed:         1<<62 - 1,
		AbsoluteCeiling: 1<<62 - 1,
		GlobalFloor:     1<<62 - 1,
		Explanation:     "bypass mode - no enforcement",
	}

	monitor := stream.NewMonitor(stream.MonitorConfig{
		UserID:   ident.UserID,
		Endpoint: endpoint,
		Role:     ident.Role,
		Decision: noEnforcementDecision,
		Engine:   p.engine,
		Enforcer: p.enforcer,
		Redis:    p.redis,
		Config:   *p.cfg,
		Logger:   p.logger,
		Cancel:   grpcCancel,
	})

	result := monitor.Stream(ctx, grpcStream, w)

	p.logger.Info("bypass request completed",
		"user_id", ident.UserID,
		"total_bytes", result.TotalBytes,
		"bypass", true,
	)
}

func (p *proxyServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"redis":     p.redis.IsAvailable(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (p *proxyServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		p.logger.Debug("incoming request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.Header.Get("User-Agent"),
		)

		next.ServeHTTP(w, r)

		p.logger.Debug("request served",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start),
		)
	})
}

func (p *proxyServer) concurrencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/health") {
			next.ServeHTTP(w, r)
			return
		}

		select {
		case p.sem <- struct{}{}:
			p.activeReq.Add(1)
			defer func() {
				<-p.sem
				p.activeReq.Done()
			}()
			next.ServeHTTP(w, r)
		default:
			p.logger.Warn("too many concurrent requests",
				"max", p.cfg.Proxy.MaxConcurrent,
			)
			http.Error(w, `{"error": "too many requests"}`, http.StatusServiceUnavailable)
		}
	})
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
