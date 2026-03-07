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

type dataServiceServer struct {
	pb.UnimplementedDataServiceServer
	cfg    *config.Config
	logger *slog.Logger
	rng    *rand.Rand
}

func (s *dataServiceServer) GetData(req *pb.DataRequest, stream pb.DataService_GetDataServer) error {
	ctx := stream.Context()
	mode := req.Mode
	if mode == pb.DataMode_DATA_MODE_UNSPECIFIED {
		mode = pb.DataMode_DATA_MODE_NORMAL
	}

	s.logger.Info("starting data stream",
		"user_id", req.UserId,
		"endpoint", req.Endpoint,
		"mode", mode.String(),
	)

	var generator func(ctx context.Context, stream pb.DataService_GetDataServer, req *pb.DataRequest) error

	switch mode {
	case pb.DataMode_DATA_MODE_NORMAL:
		generator = s.generateNormal
	case pb.DataMode_DATA_MODE_ATTACK:
		generator = s.generateAttack
	case pb.DataMode_DATA_MODE_EXPORT:
		generator = s.generateExport
	default:
		generator = s.generateNormal
	}

	if err := generator(ctx, stream, req); err != nil {
		if status.Code(err) == codes.Canceled {
			s.logger.Warn("stream cancelled by client",
				"user_id", req.UserId,
				"mode", mode.String(),
			)
			return nil
		}
		return err
	}

	return nil
}

func (s *dataServiceServer) generateNormal(ctx context.Context, stream pb.DataService_GetDataServer, req *pb.DataRequest) error {
	numChunks := 50 + s.rng.Intn(51)
	var totalBytes int64

	for i := 0; i < numChunks; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		time.Sleep(s.cfg.Backend.SimulatedLatency + time.Duration(s.rng.Intn(10))*time.Millisecond)

		rowCount := 5 + s.rng.Intn(16)
		rows := s.generateRows(rowCount, i*20)

		payload, err := json.Marshal(rows)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to marshal data: %v", err)
		}

		payload = append(payload, '\n')
		totalBytes += int64(len(payload))

		isLast := i == numChunks-1
		chunk := &pb.DataChunk{
			Payload:    payload,
			ChunkIndex: int64(i),
			TotalBytes: totalBytes,
			IsLast:     isLast,
			Metadata: map[string]string{
				"mode":        "normal",
				"rows":        fmt.Sprintf("%d", rowCount),
				"page":        fmt.Sprintf("%d", i+1),
				"total_pages": fmt.Sprintf("%d", numChunks),
			},
		}

		if err := stream.Send(chunk); err != nil {
			return err
		}
	}

	s.logger.Info("normal stream completed",
		"user_id", req.UserId,
		"chunks", numChunks,
		"total_bytes", totalBytes,
	)

	return nil
}

func (s *dataServiceServer) generateAttack(ctx context.Context, stream pb.DataService_GetDataServer, req *pb.DataRequest) error {
	numChunks := 2000 + s.rng.Intn(3001)
	var totalBytes int64

	for i := 0; i < numChunks; i++ {
		select {
		case <-ctx.Done():
			s.logger.Warn("attack stream cancelled",
				"user_id", req.UserId,
				"chunks_sent", i,
				"total_bytes", totalBytes,
			)
			return ctx.Err()
		default:
		}

		time.Sleep(time.Duration(s.rng.Intn(2)) * time.Millisecond)

		rowCount := 50 + s.rng.Intn(151)
		rows := s.generateSensitiveRows(rowCount, i*200)

		payload, err := json.Marshal(rows)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to marshal data: %v", err)
		}

		payload = append(payload, '\n')
		totalBytes += int64(len(payload))

		isLast := i == numChunks-1
		chunk := &pb.DataChunk{
			Payload:    payload,
			ChunkIndex: int64(i),
			TotalBytes: totalBytes,
			IsLast:     isLast,
			Metadata: map[string]string{
				"mode": "attack",
				"rows": fmt.Sprintf("%d", rowCount),
			},
		}

		if err := stream.Send(chunk); err != nil {
			return err
		}
	}

	s.logger.Info("attack stream completed (unrestricted)",
		"user_id", req.UserId,
		"chunks", numChunks,
		"total_bytes", totalBytes,
	)

	return nil
}

func (s *dataServiceServer) generateExport(ctx context.Context, stream pb.DataService_GetDataServer, req *pb.DataRequest) error {
	numChunks := 200 + s.rng.Intn(301)
	var totalBytes int64

	for i := 0; i < numChunks; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		time.Sleep(s.cfg.Backend.SimulatedLatency)

		rowCount := 20 + s.rng.Intn(31)
		rows := s.generateExportRows(rowCount, i*50)

		payload, err := json.Marshal(rows)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to marshal data: %v", err)
		}

		payload = append(payload, '\n')
		totalBytes += int64(len(payload))

		isLast := i == numChunks-1
		chunk := &pb.DataChunk{
			Payload:    payload,
			ChunkIndex: int64(i),
			TotalBytes: totalBytes,
			IsLast:     isLast,
			Metadata: map[string]string{
				"mode":        "export",
				"rows":        fmt.Sprintf("%d", rowCount),
				"export_page": fmt.Sprintf("%d/%d", i+1, numChunks),
			},
		}

		if err := stream.Send(chunk); err != nil {
			return err
		}
	}

	s.logger.Info("export stream completed",
		"user_id", req.UserId,
		"chunks", numChunks,
		"total_bytes", totalBytes,
	)

	return nil
}

type userRow struct {
	ID         int    `json:"id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Department string `json:"department"`
	CreatedAt  string `json:"created_at"`
}

type transactionRow struct {
	ID          int     `json:"id"`
	UserID      int     `json:"user_id"`
	Amount      float64 `json:"amount"`
	Currency    string  `json:"currency"`
	Type        string  `json:"type"`
	Status      string  `json:"status"`
	Description string  `json:"description"`
	Timestamp   string  `json:"timestamp"`
}

type sensitiveRow struct {
	ID             int     `json:"id"`
	SSN            string  `json:"ssn"`
	Email          string  `json:"email"`
	CreditCard     string  `json:"credit_card"`
	PhoneNumber    string  `json:"phone_number"`
	Address        string  `json:"address"`
	AccountBalance float64 `json:"account_balance"`
	Classification string  `json:"classification"`
}

type exportRow struct {
	ID              int    `json:"id"`
	RecordType      string `json:"record_type"`
	Timestamp       string `json:"timestamp"`
	Payload         string `json:"payload"`
	SourceSystem    string `json:"source_system"`
	ProcessingNotes string `json:"processing_notes"`
	AuditTrail      string `json:"audit_trail"`
}

var (
	departments = []string{"Engineering", "Finance", "Marketing", "Sales", "HR", "Legal", "Operations", "Support"}
	currencies  = []string{"USD", "EUR", "GBP", "JPY", "CAD", "AUD"}
	txTypes     = []string{"deposit", "withdrawal", "transfer", "payment", "refund"}
	txStatuses  = []string{"completed", "pending", "failed", "reversed"}
	firstNames  = []string{"Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry", "Iris", "Jack"}
	lastNames   = []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Wilson", "Taylor"}
	streets     = []string{"Oak St", "Maple Ave", "Main St", "Broadway", "Park Rd", "Lake Dr", "Hill Blvd", "River Way"}
	cities      = []string{"New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "San Francisco", "Seattle", "Denver"}
)

func (s *dataServiceServer) generateRows(count, offset int) []userRow {
	rows := make([]userRow, count)
	for i := range rows {
		id := offset + i + 1
		rows[i] = userRow{
			ID:         id,
			Email:      fmt.Sprintf("%s.%s%d@example.com", lower(firstNames[s.rng.Intn(len(firstNames))]), lower(lastNames[s.rng.Intn(len(lastNames))]), id),
			Name:       fmt.Sprintf("%s %s", firstNames[s.rng.Intn(len(firstNames))], lastNames[s.rng.Intn(len(lastNames))]),
			Department: departments[s.rng.Intn(len(departments))],
			CreatedAt:  time.Now().Add(-time.Duration(s.rng.Intn(365*24)) * time.Hour).Format(time.RFC3339),
		}
	}
	return rows
}

func (s *dataServiceServer) generateSensitiveRows(count, offset int) []sensitiveRow {
	rows := make([]sensitiveRow, count)
	for i := range rows {
		id := offset + i + 1
		rows[i] = sensitiveRow{
			ID:             id,
			SSN:            fmt.Sprintf("%03d-%02d-%04d", s.rng.Intn(900)+100, s.rng.Intn(100), s.rng.Intn(10000)),
			Email:          fmt.Sprintf("user%d@example.com", id),
			CreditCard:     fmt.Sprintf("%04d-%04d-%04d-%04d", s.rng.Intn(10000), s.rng.Intn(10000), s.rng.Intn(10000), s.rng.Intn(10000)),
			PhoneNumber:    fmt.Sprintf("+1-%03d-%03d-%04d", s.rng.Intn(900)+100, s.rng.Intn(900)+100, s.rng.Intn(10000)),
			Address:        fmt.Sprintf("%d %s, %s", s.rng.Intn(9999)+1, streets[s.rng.Intn(len(streets))], cities[s.rng.Intn(len(cities))]),
			AccountBalance: float64(s.rng.Intn(1000000)) / 100.0,
			Classification: "CONFIDENTIAL",
		}
	}
	return rows
}

func (s *dataServiceServer) generateExportRows(count, offset int) []exportRow {
	rows := make([]exportRow, count)
	for i := range rows {
		id := offset + i + 1
		txn := transactionRow{
			ID:          id,
			UserID:      s.rng.Intn(10000) + 1,
			Amount:      float64(s.rng.Intn(100000)) / 100.0,
			Currency:    currencies[s.rng.Intn(len(currencies))],
			Type:        txTypes[s.rng.Intn(len(txTypes))],
			Status:      txStatuses[s.rng.Intn(len(txStatuses))],
			Description: fmt.Sprintf("Transaction %d for user %d", id, s.rng.Intn(10000)+1),
			Timestamp:   time.Now().Add(-time.Duration(s.rng.Intn(30*24)) * time.Hour).Format(time.RFC3339),
		}
		txnJSON, _ := json.Marshal(txn)

		rows[i] = exportRow{
			ID:              id,
			RecordType:      "transaction_export",
			Timestamp:       time.Now().Format(time.RFC3339),
			Payload:         string(txnJSON),
			SourceSystem:    "core_banking",
			ProcessingNotes: fmt.Sprintf("Batch export record %d, compliance approved", id),
			AuditTrail:      fmt.Sprintf("export_job_%d|user_%s|approved_by_system", s.rng.Intn(1000), "automated"),
		}
	}
	return rows
}

func lower(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	if b[0] >= 'A' && b[0] <= 'Z' {
		b[0] += 32
	}
	return string(b)
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
