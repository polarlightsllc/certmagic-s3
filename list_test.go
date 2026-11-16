package s3

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type fakeListResult struct {
	XMLName        xml.Name `xml:"ListBucketResult"`
	Name           string   `xml:"Name"`
	Prefix         string   `xml:"Prefix"`
	KeyCount       int      `xml:"KeyCount"`
	IsTruncated    bool     `xml:"IsTruncated"`
	Contents       []fakeObject
	CommonPrefixes []fakePrefix
}

type fakeObject struct {
	XMLName xml.Name `xml:"Contents"`
	Key     string   `xml:"Key"`
}

type fakePrefix struct {
	XMLName xml.Name `xml:"CommonPrefixes"`
	Prefix  string   `xml:"Prefix"`
}

// newFakeBucket serves ListObjectsV2 and GetObject for an in-memory bucket.
func newFakeBucket(t *testing.T, objects map[string]string) *S3 {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/bucket")
		key = strings.TrimPrefix(key, "/")
		if key != "" {
			body, ok := objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code></Error>`))
				return
			}
			_, _ = w.Write([]byte(body))
			return
		}

		prefix := r.URL.Query().Get("prefix")
		delimiter := r.URL.Query().Get("delimiter")
		res := fakeListResult{Name: "bucket", Prefix: prefix}
		seen := map[string]bool{}
		var names []string
		for k := range objects {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if !strings.HasPrefix(k, prefix) {
				continue
			}
			rest := strings.TrimPrefix(k, prefix)
			if delimiter != "" {
				if i := strings.Index(rest, delimiter); i >= 0 {
					cp := prefix + rest[:i+1]
					if !seen[cp] {
						seen[cp] = true
						res.CommonPrefixes = append(res.CommonPrefixes, fakePrefix{Prefix: cp})
					}
					continue
				}
			}
			res.Contents = append(res.Contents, fakeObject{Key: k})
		}
		res.KeyCount = len(res.Contents) + len(res.CommonPrefixes)
		w.Header().Set("Content-Type", "application/xml")
		_ = xml.NewEncoder(w).Encode(res)
	}))
	t.Cleanup(srv.Close)

	storage := &S3{
		Logger:    zap.NewNop(),
		Endpoint:  srv.URL,
		Bucket:    "bucket",
		Region:    "us-east-1",
		AccessKey: "test-access",
		SecretKey: "test-secret",
		Prefix:    "caddy",
		iowrap:    &CleartextIO{},
	}
	storage.UsePathStyle = true
	client, err := storage.buildS3Client()
	if err != nil {
		t.Fatalf("buildS3Client() error = %v", err)
	}
	storage.Client = client
	return storage
}

func TestS3_ListReturnsLoadableKeys(t *testing.T) {
	storage := newFakeBucket(t, map[string]string{
		"caddy/ocsp/example.com-abc":                             "staple",
		"caddy/ocsp/other.com-def":                               "staple",
		"caddy/certificates/acme/example.com/example.com.crt":    "crt",
		"caddy/certificates/acme/example.com/example.com.key":    "key",
		"caddy/certificates/acme/other.com/other.com.crt":        "crt",
		"caddy/certificates/zerossl/example.org/example.org.crt": "crt",
		"caddy/last_clean.json":                                  "{}",
		"caddyx/ocsp/unrelated":                                  "nope",
		"elsewhere/caddy/ocsp/unrelated":                         "nope",
	})
	ctx := context.Background()

	tests := []struct {
		prefix    string
		recursive bool
		want      []string
	}{
		{"ocsp", false, []string{"ocsp/example.com-abc", "ocsp/other.com-def"}},
		{"certificates", false, []string{"certificates/acme", "certificates/zerossl"}},
		{"certificates/acme", false, []string{"certificates/acme/example.com", "certificates/acme/other.com"}},
		{"certificates/acme/example.com", false, []string{
			"certificates/acme/example.com/example.com.crt",
			"certificates/acme/example.com/example.com.key",
		}},
		{"certificates", true, []string{
			"certificates/acme/example.com/example.com.crt",
			"certificates/acme/example.com/example.com.key",
			"certificates/acme/other.com/other.com.crt",
			"certificates/zerossl/example.org/example.org.crt",
		}},
		{"missing", false, nil},
	}

	for _, tt := range tests {
		got, err := storage.List(ctx, tt.prefix, tt.recursive)
		if err != nil {
			t.Fatalf("List(%q, %v) error = %v", tt.prefix, tt.recursive, err)
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("List(%q, %v) = %v, want %v", tt.prefix, tt.recursive, got, tt.want)
		}
	}

	keys, err := storage.List(ctx, "ocsp", false)
	if err != nil {
		t.Fatalf("List(ocsp) error = %v", err)
	}
	for _, key := range keys {
		if _, err := storage.Load(ctx, key); err != nil {
			t.Errorf("Load(%q) of a listed key error = %v", key, err)
		}
	}
}

func TestS3_LogObjectRedactsSecrets(t *testing.T) {
	var buf bytes.Buffer
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&buf),
		zapcore.DebugLevel,
	)
	storage := &S3{
		Endpoint:      "https://storage.googleapis.com",
		Bucket:        "bucket",
		Region:        "us-east-1",
		AccessKey:     "AKIA-should-not-leak",
		SecretKey:     "secret-should-not-leak",
		EncryptionKey: "0123456789abcdef0123456789abcdef",
		Prefix:        "caddy",
	}

	zap.New(core).Error("storage error", zap.Any("storage", storage))

	out := buf.String()
	for _, secret := range []string{storage.AccessKey, storage.SecretKey, storage.EncryptionKey} {
		if strings.Contains(out, secret) {
			t.Fatalf("log output leaks %q: %s", secret, out)
		}
	}

	var entry struct {
		Storage map[string]any `json:"storage"`
	}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log line: %v", err)
	}
	if entry.Storage["bucket"] != "bucket" || entry.Storage["encrypted"] != true {
		t.Fatalf("unexpected storage log fields: %v", entry.Storage)
	}
}
