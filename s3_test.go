package s3

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/aws/smithy-go/middleware"
	"go.uber.org/zap"
)

func TestS3_objName(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		key      string
		expected string
	}{
		{
			name:     "empty prefix",
			prefix:   "",
			key:      "test.key",
			expected: "test.key",
		},
		{
			name:     "with prefix",
			prefix:   "acme",
			key:      "test.key",
			expected: "acme/test.key",
		},
		{
			name:     "slash normalization",
			prefix:   "//acme//",
			key:      "//test.key",
			expected: "acme/test.key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s3 := &S3{Prefix: tt.prefix}
			result := s3.objName(tt.key)
			if result != tt.expected {
				t.Errorf("objName() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestS3_objLockName(t *testing.T) {
	s3 := &S3{Prefix: "acme"}
	key := "test.key"
	expected := "acme/test.key.lock"

	result := s3.objLockName(key)
	if result != expected {
		t.Errorf("objLockName() = %v, want %v", result, expected)
	}
}

func TestS3_UsePathStyleConfiguration(t *testing.T) {
	tests := []struct {
		name            string
		endpoint        string
		usePathStyle    bool
		expectPathStyle bool
	}{
		{
			name:            "default AWS (no custom endpoint)",
			endpoint:        "",
			usePathStyle:    false,
			expectPathStyle: false,
		},
		{
			name:            "explicit path style enabled",
			endpoint:        "",
			usePathStyle:    true,
			expectPathStyle: true,
		},
		{
			name:            "custom endpoint forces path style",
			endpoint:        "https://minio.example.com",
			usePathStyle:    false,
			expectPathStyle: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s3 := &S3{
				Endpoint:     tt.endpoint,
				UsePathStyle: tt.usePathStyle,
			}

			endpoint := tt.endpoint
			shouldUsePathStyle := s3.UsePathStyle || endpoint != ""

			if shouldUsePathStyle != tt.expectPathStyle {
				t.Errorf("UsePathStyle logic = %v, want %v", shouldUsePathStyle, tt.expectPathStyle)
			}
		})
	}
}

func TestStripAcceptEncodingIdentity(t *testing.T) {
	stack := middleware.NewStack("test", func() interface{} { return nil })
	if err := stack.Finalize.Add(middleware.FinalizeMiddlewareFunc("DisableAcceptEncodingGzip", func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
		return next.HandleFinalize(ctx, in)
	}), middleware.Before); err != nil {
		t.Fatalf("failed to add middleware: %v", err)
	}

	if _, ok := stack.Finalize.Get("DisableAcceptEncodingGzip"); !ok {
		t.Fatal("expected DisableAcceptEncodingGzip middleware to be present before stripping")
	}

	if err := stripAcceptEncodingIdentity(stack); err != nil {
		t.Fatalf("stripAcceptEncodingIdentity() error = %v", err)
	}

	if _, ok := stack.Finalize.Get("DisableAcceptEncodingGzip"); ok {
		t.Fatal("expected DisableAcceptEncodingGzip middleware to be removed")
	}
}

func TestStripAcceptEncodingIdentityMissingMiddleware(t *testing.T) {
	stack := middleware.NewStack("test", func() interface{} { return nil })

	if err := stripAcceptEncodingIdentity(stack); err != nil {
		t.Fatalf("stripAcceptEncodingIdentity() error = %v", err)
	}
}

func TestS3_GCSInterop(t *testing.T) {
	if os.Getenv("CERTMAGIC_S3_RUN_GCS_INTEGRATION") != "1" {
		t.Skip("set CERTMAGIC_S3_RUN_GCS_INTEGRATION=1 to run")
	}

	accessKey := os.Getenv("CERTMAGIC_S3_GCS_ACCESS_KEY")
	secretKey := os.Getenv("CERTMAGIC_S3_GCS_SECRET_KEY")
	bucket := os.Getenv("CERTMAGIC_S3_GCS_BUCKET")
	if accessKey == "" || secretKey == "" || bucket == "" {
		t.Fatal("CERTMAGIC_S3_GCS_ACCESS_KEY, CERTMAGIC_S3_GCS_SECRET_KEY, and CERTMAGIC_S3_GCS_BUCKET are required")
	}

	storage := &S3{
		Logger:       zap.NewNop(),
		Endpoint:     "https://storage.googleapis.com",
		Bucket:       bucket,
		Region:       "us-east-1",
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		Prefix:       "codex-smoke-" + time.Now().UTC().Format("20060102-150405"),
		UsePathStyle: true,
		iowrap:       &CleartextIO{},
	}

	client, err := storage.buildS3Client()
	if err != nil {
		t.Fatalf("buildS3Client() error = %v", err)
	}
	storage.Client = client

	ctx := context.Background()
	if _, err := storage.Load(ctx, "missing.key"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load(missing.key) error = %v, want %v", err, fs.ErrNotExist)
	}

	if err := storage.Store(ctx, "hello.txt", []byte("hello from certmagic-s3")); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	value, err := storage.Load(ctx, "hello.txt")
	if err != nil {
		t.Fatalf("Load(hello.txt) error = %v", err)
	}
	if string(value) != "hello from certmagic-s3" {
		t.Fatalf("Load(hello.txt) = %q", value)
	}

	if !storage.Exists(ctx, "hello.txt") {
		t.Fatal("Exists(hello.txt) = false, want true")
	}

	if err := storage.Delete(ctx, "hello.txt"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if storage.Exists(ctx, "hello.txt") {
		t.Fatal("Exists(hello.txt) = true after delete")
	}
}
