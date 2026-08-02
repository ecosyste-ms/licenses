package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/ecosyste-ms/licenses/internal/handler"
	"github.com/ecosyste-ms/licenses/internal/scanner"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	scanService, err := scanner.New()
	if err != nil {
		return err
	}
	if err := configureLimits(scanService); err != nil {
		return err
	}
	requestTimeout, err := durationEnv("SCAN_TIMEOUT", 120*time.Second)
	if err != nil {
		return err
	}
	maxConcurrent, err := positiveIntEnv("MAX_CONCURRENT_SCANS", 4)
	if err != nil {
		return err
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}
	openAPIPath := os.Getenv("OPENAPI_PATH")
	if openAPIPath == "" {
		openAPIPath = filepath.Join("openapi", "api", "v2", "openapi.yaml")
	}
	application, err := handler.New(scanService, maxConcurrent, requestTimeout, openAPIPath)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           application,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      requestTimeout + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	shutdownSignals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownSignals.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
		}
	}()

	slog.Info("starting Go v2 license service", "port", port, "max_concurrent_scans", maxConcurrent)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func positiveIntEnv(name string, fallback int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return value, nil
}

func positiveInt64Env(name string, fallback int64) (int64, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func configureLimits(scanService *scanner.Scanner) error {
	var err error
	if scanService.ArchiveClient.Limits.MaxBytes, err = positiveInt64Env(
		"MAX_DOWNLOAD_BYTES", scanService.ArchiveClient.Limits.MaxBytes,
	); err != nil {
		return err
	}
	if scanService.ExtractLimits.MaxEntries, err = positiveIntEnv(
		"MAX_ARCHIVE_ENTRIES", scanService.ExtractLimits.MaxEntries,
	); err != nil {
		return err
	}
	if scanService.ExtractLimits.MaxDepth, err = positiveIntEnv(
		"MAX_ARCHIVE_DEPTH", scanService.ExtractLimits.MaxDepth,
	); err != nil {
		return err
	}
	if scanService.ExtractLimits.MaxEntryBytes, err = positiveInt64Env(
		"MAX_ENTRY_BYTES", scanService.ExtractLimits.MaxEntryBytes,
	); err != nil {
		return err
	}
	if scanService.ExtractLimits.MaxExpandedBytes, err = positiveInt64Env(
		"MAX_EXPANDED_BYTES", scanService.ExtractLimits.MaxExpandedBytes,
	); err != nil {
		return err
	}
	if scanService.Limits.MaxFiles, err = positiveIntEnv("MAX_SCAN_FILES", scanService.Limits.MaxFiles); err != nil {
		return err
	}
	if scanService.Limits.MaxDepth, err = positiveIntEnv("MAX_SCAN_DEPTH", scanService.Limits.MaxDepth); err != nil {
		return err
	}
	if scanService.Limits.MaxFileBytes, err = positiveInt64Env(
		"MAX_SCAN_FILE_BYTES", scanService.Limits.MaxFileBytes,
	); err != nil {
		return err
	}
	if scanService.Limits.Workers, err = positiveIntEnv("SCAN_WORKERS", scanService.Limits.Workers); err != nil {
		return err
	}
	if scanService.Limits.MaxAttributionFiles, err = positiveIntEnv(
		"MAX_ATTRIBUTION_FILES", scanService.Limits.MaxAttributionFiles,
	); err != nil {
		return err
	}
	if scanService.Limits.MaxAttributionBytes, err = positiveInt64Env(
		"MAX_ATTRIBUTION_BYTES", scanService.Limits.MaxAttributionBytes,
	); err != nil {
		return err
	}
	if scanService.ExtractLimits.MaxEntryBytes > scanService.ExtractLimits.MaxExpandedBytes {
		return errors.New("MAX_ENTRY_BYTES must not exceed MAX_EXPANDED_BYTES")
	}
	return nil
}
