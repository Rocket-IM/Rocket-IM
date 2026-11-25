// im-service 是独立Go运行产物；只支持显式固定设备的本机开发Alpha。
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"rocket-im/service/internal/storage"
	"rocket-im/service/internal/transport"
	"syscall"
	"time"
)

func run() error {
	path := flag.String("config", "", "显式JSON配置路径")
	operation := flag.String("operation", "serve", "serve / enroll / backup / restore / enable-reconciliation / reconcile / enable-capacity-reserve / enable-capacity-workset / enable-repeated-workset")
	backup := flag.String("backup", "", "规范绝对备份文件路径")
	version := flag.Bool("version", false, "显示Service产物版本")
	flag.Parse()
	if *version {
		fmt.Println(storage.ServiceVersion)
		return nil
	}
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	if *operation != "serve" {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		result, err := storage.Maintain(ctx, c, *operation, *backup)
		if err != nil {
			return errors.New(m.ErrorCode(err))
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, e := storage.Open(ctx, c)
	if e != nil {
		return errors.New(m.ErrorCode(e))
	}
	defer store.Close()
	handler := transport.New(store)
	defer handler.Close()
	server := &http.Server{Addr: c.Listen, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS(c.TLSCert, c.TLSKey) }()
	log.Print("Rocket-IM " + storage.ServiceVersion + " starting; fixed test devices; TLS required")
	select {
	case e = <-done:
		if !errors.Is(e, http.ErrServerClosed) {
			return errors.New("listen_failed")
		}
		return nil
	case <-signals.Done():
	}
	handler.Close()
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if e = server.Shutdown(shutdown); e != nil {
		return errors.New("shutdown_failed")
	}
	if e = handler.Drain(shutdown); e != nil {
		return errors.New("shutdown_drain_failed")
	}
	if e = store.Seal(shutdown); e != nil {
		return errors.New(m.ErrorCode(e))
	}
	if c.RecoveryState != "" {
		log.Print("Service maintenance checkpoint sealed")
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		log.Print(e.Error())
		os.Exit(1)
	}
}
