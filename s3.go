package s3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	s3sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

var ErrInvalidKey = errors.New("invalid key")

type S3 struct {
	Logger *zap.Logger

	// S3
	Client       *s3sdk.Client
	Host         string `json:"host"`
	Endpoint     string `json:"endpoint"`
	Insecure     bool   `json:"insecure"`
	Bucket       string `json:"bucket"`
	Region       string `json:"region"`
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	Profile      string `json:"profile"`
	RoleARN      string `json:"role_arn"`
	Prefix       string `json:"prefix"`
	UsePathStyle bool   `json:"use_path_style,omitempty"`

	// EncryptionKey is optional. If you do not wish to encrypt your certficates and key inside the S3 bucket, leave it empty.
	EncryptionKey string `json:"encryption_key"`

	iowrap IO

	// locks tracks the refresh goroutine for each held lock, keyed by lock key.
	locks *sync.Map
}

func init() {
	caddy.RegisterModule(new(S3))
}

func (s3 *S3) Provision(ctx caddy.Context) error {
	s3.Logger = ctx.Logger(s3)
	s3.locks = &sync.Map{}

	if s3.Host != "" {
		s3.Logger.Info("Using deprecated 'host' option, consider switching to 'endpoint'",
			zap.String("host", s3.Host),
			zap.String("endpoint", s3.Endpoint),
		)
	}

	client, err := s3.buildS3Client()
	if err != nil {
		return fmt.Errorf("failed to create S3 client: %w", err)
	}

	s3.Client = client
	return s3.setupEncryption()
}

func (s3 *S3) buildS3Client() (*s3sdk.Client, error) {
	configOptions := []func(*config.LoadOptions) error{
		config.WithRegion(s3.Region),
	}

	if s3.Endpoint != "" {
		// some non-AWS providers do not implement automatic checksums
		// see https://github.com/aws/aws-sdk-go-v2/discussions/2960 for more details
		configOptions = append(configOptions, config.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired))
	}

	if s3.Insecure {
		s3.Logger.Warn("TLS certificate verification is disabled - this is insecure and should only be used for testing")
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // #nosec G402
				},
			},
		}
		configOptions = append(configOptions, config.WithHTTPClient(httpClient))
	}

	if s3.AccessKey != "" && s3.SecretKey != "" {
		configOptions = append(configOptions, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(s3.AccessKey, s3.SecretKey, "")))
	} else if s3.Profile != "" {
		configOptions = append(configOptions, config.WithSharedConfigProfile(s3.Profile))
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), configOptions...)
	if err != nil {
		return nil, err
	}

	if s3.RoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, s3.RoleARN)
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}

	var s3Options []func(*s3sdk.Options)

	if s3.Endpoint != "" {
		s3Options = append(s3Options, func(o *s3sdk.Options) {
			o.BaseEndpoint = aws.String(s3.Endpoint)
		})
		s3Options = append(s3Options, func(o *s3sdk.Options) {
			o.APIOptions = append(o.APIOptions, stripAcceptEncodingIdentity)
		})
	}

	if s3.UsePathStyle {
		s3Options = append(s3Options, func(o *s3sdk.Options) {
			o.UsePathStyle = true
		})
	}

	return s3sdk.NewFromConfig(cfg, s3Options...), nil
}

func stripAcceptEncodingIdentity(stack *middleware.Stack) error {
	_, _ = stack.Finalize.Remove("DisableAcceptEncodingGzip")
	return nil
}

func (s3 *S3) setupEncryption() error {
	if len(s3.EncryptionKey) == 0 {
		s3.Logger.Info("Clear text certificate storage active")
		s3.iowrap = &CleartextIO{}
	} else if len(s3.EncryptionKey) != 32 {
		s3.Logger.Error("encryption key must have exactly 32 bytes")
		return errors.New("encryption key must have exactly 32 bytes")
	} else {
		s3.Logger.Info("Encrypted certificate storage active")
		sb := &SecretBoxIO{}
		copy(sb.SecretKey[:], []byte(s3.EncryptionKey))
		s3.iowrap = sb
	}

	return nil
}

func (s3 *S3) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.s3",
		New: func() caddy.Module {
			return new(S3)
		},
	}
}

var (
	// LockExpiration is how long a held lock may go without a refresh before
	// another instance is allowed to steal it (e.g. after a crash). It must be
	// safely larger than LockRefreshInterval.
	LockExpiration = 2 * time.Minute
	// LockPollInterval is how long to wait between attempts to acquire a lock
	// that is currently held by someone else.
	LockPollInterval = 1 * time.Second
	// LockRefreshInterval is how often a held lock's timestamp is rewritten so
	// it does not appear stale while issuance (which certmagic serializes under
	// this lock across its full retry sequence) is still in progress.
	LockRefreshInterval = 30 * time.Second
)

// Lock acquires a distributed lock for key, blocking until it is obtained or
// ctx is cancelled. Acquisition is atomic: the lock object is created with a
// conditional (create-only) PutObject, so concurrent callers across instances
// can never both believe they hold the lock. Once held, the lock is refreshed
// in the background until Unlock so long-running issuance is not stolen.
func (s3 *S3) Lock(ctx context.Context, key string) error {
	s3.Logger.Info(fmt.Sprintf("Lock: %v", s3.objName(key)))

	for {
		err := s3.putLockFile(ctx, key, true)
		if err == nil {
			s3.startLockRefresh(key)
			return nil
		}
		if !isPreconditionFailed(err) {
			// Transient error (network, etc.): back off and retry.
			if waitErr := sleepOrDone(ctx, LockPollInterval); waitErr != nil {
				return waitErr
			}
			continue
		}

		// Lock already exists. Steal it only if it has gone stale; the steal is
		// race-safe because the subsequent create is itself atomic.
		if s3.lockIsStale(ctx, key) {
			_ = s3.deleteLockFile(ctx, key)
			continue
		}

		if waitErr := sleepOrDone(ctx, LockPollInterval); waitErr != nil {
			return waitErr
		}
	}
}

// putLockFile writes the lock object with the current timestamp. When createOnly
// is true it uses a conditional write (If-None-Match: *) so the PutObject only
// succeeds if no lock object exists, giving atomic acquisition.
func (s3 *S3) putLockFile(ctx context.Context, key string, createOnly bool) error {
	lockData := []byte(time.Now().Format(time.RFC3339))
	r := bytes.NewReader(lockData)

	input := &s3sdk.PutObjectInput{
		Bucket:        aws.String(s3.Bucket),
		Key:           aws.String(s3.objLockName(key)),
		Body:          r,
		ContentLength: aws.Int64(int64(len(lockData))),
	}
	if createOnly {
		input.IfNoneMatch = aws.String("*")
	}

	_, err := s3.Client.PutObject(ctx, input)
	return err
}

// lockIsStale reports whether the existing lock object is older than
// LockExpiration (or missing/unparseable), meaning it may be stolen.
func (s3 *S3) lockIsStale(ctx context.Context, key string) bool {
	input := &s3sdk.GetObjectInput{
		Bucket: aws.String(s3.Bucket),
		Key:    aws.String(s3.objLockName(key)),
	}

	result, err := s3.Client.GetObject(ctx, input)
	if err != nil {
		var nsk *types.NoSuchKey
		// Lock vanished between attempts: treat as acquirable.
		return errors.As(err, &nsk)
	}
	defer func() { _ = result.Body.Close() }()

	buf, err := io.ReadAll(result.Body)
	if err != nil {
		return false
	}

	lt, err := time.Parse(time.RFC3339, string(buf))
	if err != nil {
		// Lock file does not make sense, allow overwrite.
		return true
	}
	return time.Now().After(lt.Add(LockExpiration))
}

func (s3 *S3) deleteLockFile(ctx context.Context, key string) error {
	input := &s3sdk.DeleteObjectInput{
		Bucket: aws.String(s3.Bucket),
		Key:    aws.String(s3.objLockName(key)),
	}
	_, err := s3.Client.DeleteObject(ctx, input)
	return err
}

// startLockRefresh keeps a held lock fresh by periodically rewriting its
// timestamp until the lock is released via Unlock.
func (s3 *S3) startLockRefresh(key string) {
	refreshCtx, cancel := context.WithCancel(context.Background())
	if prev, loaded := s3.locks.Swap(key, cancel); loaded {
		// Defensive: cancel any orphaned refresher for the same key.
		prev.(context.CancelFunc)()
	}

	go func() {
		ticker := time.NewTicker(LockRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-refreshCtx.Done():
				return
			case <-ticker.C:
				if err := s3.putLockFile(refreshCtx, key, false); err != nil && refreshCtx.Err() == nil {
					s3.Logger.Warn("failed to refresh lock",
						zap.String("key", s3.objLockName(key)),
						zap.Error(err),
					)
				}
			}
		}
	}()
}

func (s3 *S3) Unlock(ctx context.Context, key string) error {
	s3.Logger.Info(fmt.Sprintf("Release lock: %v", s3.objName(key)))

	if cancel, ok := s3.locks.LoadAndDelete(key); ok {
		cancel.(context.CancelFunc)()
	}

	if err := s3.deleteLockFile(ctx, key); err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) || isNotFound(err) {
			// Already released: not an error.
			return nil
		}
		return err
	}
	return nil
}

func sleepOrDone(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isPreconditionFailed(err error) bool {
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode() == http.StatusPreconditionFailed
	}
	return false
}

func isNotFound(err error) bool {
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode() == http.StatusNotFound
	}
	return false
}

func (s3 *S3) Store(ctx context.Context, key string, value []byte) error {
	start := time.Now()
	objName := s3.objName(key)

	if len(value) == 0 {
		return fmt.Errorf("%w: cannot store empty value", ErrInvalidKey)
	}

	s3.Logger.Info("storing object",
		zap.String("key", objName),
		zap.Int("size", len(value)),
		zap.String("bucket", s3.Bucket),
	)

	defer func() {
		s3.Logger.Debug("store completed",
			zap.String("key", objName),
			zap.Duration("duration", time.Since(start)),
		)
	}()

	r := s3.iowrap.ByteReader(value)

	input := &s3sdk.PutObjectInput{
		Bucket:        aws.String(s3.Bucket),
		Key:           aws.String(objName),
		Body:          &r,
		ContentLength: aws.Int64(r.Len()),
	}

	_, err := s3.Client.PutObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to store key %s: %w", key, err)
	}
	return nil
}

func (s3 *S3) Load(ctx context.Context, key string) ([]byte, error) {
	start := time.Now()
	objName := s3.objName(key)

	s3.Logger.Info("loading object",
		zap.String("key", objName),
		zap.String("bucket", s3.Bucket),
	)

	defer func() {
		s3.Logger.Debug("load completed",
			zap.String("key", objName),
			zap.Duration("duration", time.Since(start)),
		)
	}()

	input := &s3sdk.GetObjectInput{
		Bucket: aws.String(s3.Bucket),
		Key:    aws.String(objName),
	}

	result, err := s3.Client.GetObject(ctx, input)
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("failed to load key %s: %w", key, err)
	}
	defer func() { _ = result.Body.Close() }()

	buf, err := io.ReadAll(s3.iowrap.WrapReader(result.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to read/decrypt data for key %s: %w", key, err)
	}
	return buf, nil
}

func (s3 *S3) Delete(ctx context.Context, key string) error {
	start := time.Now()
	objName := s3.objName(key)

	s3.Logger.Info("deleting object",
		zap.String("key", objName),
		zap.String("bucket", s3.Bucket),
	)

	defer func() {
		s3.Logger.Debug("delete completed",
			zap.String("key", objName),
			zap.Duration("duration", time.Since(start)),
		)
	}()

	input := &s3sdk.DeleteObjectInput{
		Bucket: aws.String(s3.Bucket),
		Key:    aws.String(objName),
	}

	_, err := s3.Client.DeleteObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete key %s: %w", key, err)
	}
	return nil
}

func (s3 *S3) Exists(ctx context.Context, key string) bool {
	objName := s3.objName(key)

	s3.Logger.Debug("checking object existence",
		zap.String("key", objName),
		zap.String("bucket", s3.Bucket),
	)

	input := &s3sdk.HeadObjectInput{
		Bucket: aws.String(s3.Bucket),
		Key:    aws.String(objName),
	}

	_, err := s3.Client.HeadObject(ctx, input)
	exists := err == nil

	s3.Logger.Debug("existence check completed",
		zap.String("key", objName),
		zap.Bool("exists", exists),
	)

	return exists
}

func (s3 *S3) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var keys []string

	input := &s3sdk.ListObjectsV2Input{
		Bucket: aws.String(s3.Bucket),
		Prefix: aws.String(s3.objName("")),
	}

	paginator := s3sdk.NewListObjectsV2Paginator(s3.Client, input)
	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, obj := range result.Contents {
			keys = append(keys, aws.ToString(obj.Key))
		}
	}

	return keys, nil
}

func (s3 *S3) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	s3.Logger.Info(fmt.Sprintf("Stat: %v", s3.objName(key)))
	var ki certmagic.KeyInfo

	input := &s3sdk.HeadObjectInput{
		Bucket: aws.String(s3.Bucket),
		Key:    aws.String(s3.objName(key)),
	}

	result, err := s3.Client.HeadObject(ctx, input)
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return ki, fs.ErrNotExist
		}
		return ki, err
	}

	ki.Key = key
	ki.Size = aws.ToInt64(result.ContentLength)
	ki.Modified = aws.ToTime(result.LastModified)
	ki.IsTerminal = true
	return ki, nil
}

func (s3 *S3) objName(key string) string {
	prefix := strings.Trim(s3.Prefix, "/")
	key = strings.TrimLeft(key, "/")

	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}

func (s3 *S3) objLockName(key string) string {
	return s3.objName(key) + ".lock"
}

// CertMagicStorage converts s to a certmagic.Storage instance.
func (s3 *S3) CertMagicStorage() (certmagic.Storage, error) {
	return s3, nil
}

func parseBool(value string) (bool, error) {
	return strconv.ParseBool(value)
}

func (s3 *S3) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		key := d.Val()
		var value string

		if !d.Args(&value) {
			continue
		}

		switch key {
		case "host":
			s3.Host = value
		case "endpoint":
			s3.Endpoint = value
		case "insecure":
			parsed, err := parseBool(value)
			if err != nil {
				return d.Errf("invalid boolean value for 'insecure': %v", err)
			}
			s3.Insecure = parsed
		case "bucket":
			s3.Bucket = value
		case "region":
			s3.Region = value
		case "access_key":
			s3.AccessKey = value
		case "secret_key":
			s3.SecretKey = value
		case "profile":
			s3.Profile = value
		case "role_arn":
			s3.RoleARN = value
		case "prefix":
			s3.Prefix = value
		case "encryption_key":
			if value != "" && len(value) != 32 {
				return d.Errf("encryption_key must be exactly 32 bytes, got %d", len(value))
			}
			s3.EncryptionKey = value
		case "use_path_style":
			parsed, err := parseBool(value)
			if err != nil {
				return d.Errf("invalid boolean value for 'use_path_style': %v", err)
			}
			s3.UsePathStyle = parsed
		default:
			return d.Errf("unknown configuration option: %s", key)
		}
	}

	if s3.Region == "" {
		s3.Region = "us-east-1"
	}
	if s3.Prefix == "" {
		s3.Prefix = "acme"
	}

	if s3.Bucket == "" {
		return d.Err("bucket is required")
	}

	if s3.Host != "" && s3.Endpoint != "" {
		return d.Err("cannot specify both 'host' and 'endpoint' options")
	}
	if s3.Host != "" && s3.Endpoint == "" {
		s3.Endpoint = "https://" + s3.Host
	}
	if s3.Endpoint != "" && !s3.UsePathStyle {
		s3.UsePathStyle = true
	}

	return nil
}

var (
	_ caddy.Provisioner      = (*S3)(nil)
	_ caddy.StorageConverter = (*S3)(nil)
	_ caddyfile.Unmarshaler  = (*S3)(nil)
)
