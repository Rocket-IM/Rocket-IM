// Package db 保存嵌入的迁移和手写SQL，Service运行无需源码路径。
package db

import "embed"

//go:embed migrations/*.sql queries/*.sql
var Files embed.FS
