package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/rotate"
	"golang.org/x/crypto/nacl/box"
)

type mockBackend struct {
	mu              sync.Mutex
	pubKey          *[32]byte
	privKey         *[32]byte
	iamKeys         []mockIAMKey
	failPutRepo     string
	createCalls     int
	putCalls        int
	stsCalls        int
	deactivatedKeys []string
	deletedKeys     []string
	decryptedValues map[string]string
}

type mockIAMKey struct {
	id     string
	status string
}

type backendSnapshot struct {
	createCalls     int
	putCalls        int
	stsCalls        int
	deactivatedKeys []string
	deletedKeys     []string
	decryptedValues map[string]string
}

func (m *mockBackend) snapshot() backendSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	decrypted := make(map[string]string, len(m.decryptedValues))
	for k, v := range m.decryptedValues {
		decrypted[k] = v
	}
	return backendSnapshot{
		createCalls:     m.createCalls,
		putCalls:        m.putCalls,
		stsCalls:        m.stsCalls,
		deactivatedKeys: slices.Clone(m.deactivatedKeys),
		deletedKeys:     slices.Clone(m.deletedKeys),
		decryptedValues: decrypted,
	}
}

func (m *mockBackend) reset(failPutRepo string, keys ...mockIAMKey) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.failPutRepo = failPutRepo
	m.iamKeys = slices.Clone(keys)
	m.deactivatedKeys = nil
	m.deletedKeys = nil
	return m.createCalls
}

func newMockBackend(t *testing.T) *mockBackend {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey failed: %v", err)
	}
	return &mockBackend{
		pubKey:          pub,
		privKey:         priv,
		iamKeys:         []mockIAMKey{{id: "AKIA_OLD_ACTIVE", status: "Active"}},
		decryptedValues: make(map[string]string),
	}
}

func (m *mockBackend) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// AWS CloudTrail uses X-Amz-Target JSON 1.1.
		if target := r.Header.Get("X-Amz-Target"); strings.Contains(target, "CloudTrail") {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Events": []map[string]any{
					{
						"CloudTrailEvent": `{"userAgent":"github-actions/runner","sourceIPAddress":"140.82.112.1","userIdentity":{"accessKeyId":"AKIA_OLD_ACTIVE"}}`,
					},
				},
			})
			return
		}

		// AWS IAM & STS Query APIs send POST / with form Action=...
		if r.Method == http.MethodPost && r.URL.Path == "/" {
			_ = r.ParseForm()
			action := r.FormValue("Action")
			m.handleAWSQuery(w, action, r)
			return
		}

		// GitHub REST API endpoints.
		m.handleGitHubREST(w, r)
	}))
}

func (m *mockBackend) handleAWSQuery(w http.ResponseWriter, action string, r *http.Request) {
	w.Header().Set("Content-Type", "text/xml")
	m.mu.Lock()
	defer m.mu.Unlock()

	switch action {
	case "ListUsers":
		_, _ = fmt.Fprint(w, `<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListUsersResult><Users><member><UserName>ci-deployer</UserName><UserId>AIDA1</UserId><Arn>arn:aws:iam::123456789012:user/ci-deployer</Arn><Path>/</Path><CreateDate>2026-01-01T00:00:00Z</CreateDate></member></Users><IsTruncated>false</IsTruncated></ListUsersResult></ListUsersResponse>`)
	case "ListAccessKeys":
		var members strings.Builder
		for _, k := range m.iamKeys {
			fmt.Fprintf(&members, `<member><UserName>ci-deployer</UserName><AccessKeyId>%s</AccessKeyId><Status>%s</Status><CreateDate>2026-01-01T00:00:00Z</CreateDate></member>`, k.id, k.status)
		}
		_, _ = fmt.Fprintf(w, `<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListAccessKeysResult><AccessKeyMetadata>%s</AccessKeyMetadata><IsTruncated>false</IsTruncated></ListAccessKeysResult></ListAccessKeysResponse>`, members.String())
	case "GetAccessKeyLastUsed":
		_, _ = fmt.Fprint(w, `<GetAccessKeyLastUsedResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetAccessKeyLastUsedResult><UserName>ci-deployer</UserName><AccessKeyLastUsed><LastUsedDate>2026-11-24T00:00:00Z</LastUsedDate><ServiceName>s3</ServiceName><Region>us-east-1</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>`)
	case "ListAttachedUserPolicies":
		_, _ = fmt.Fprint(w, `<ListAttachedUserPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListAttachedUserPoliciesResult><AttachedPolicies><member><PolicyName>AdministratorAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn></member></AttachedPolicies><IsTruncated>false</IsTruncated></ListAttachedUserPoliciesResult></ListAttachedUserPoliciesResponse>`)
	case "ListUserPolicies":
		_, _ = fmt.Fprint(w, `<ListUserPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListUserPoliciesResult><PolicyNames></PolicyNames><IsTruncated>false</IsTruncated></ListUserPoliciesResult></ListUserPoliciesResponse>`)
	case "CreateAccessKey":
		m.createCalls++
		m.iamKeys = append(m.iamKeys, mockIAMKey{id: "AKIA_MINTED_NEW", status: "Active"})
		_, _ = fmt.Fprint(w, `<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><CreateAccessKeyResult><AccessKey><UserName>ci-deployer</UserName><AccessKeyId>AKIA_MINTED_NEW</AccessKeyId><Status>Active</Status><SecretAccessKey>e2eSecretAccessKeyValueDoNotLeak</SecretAccessKey><CreateDate>2026-11-25T12:00:00Z</CreateDate></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`)
	case "UpdateAccessKey":
		keyID := r.FormValue("AccessKeyId")
		status := r.FormValue("Status")
		if status == "Inactive" {
			m.deactivatedKeys = append(m.deactivatedKeys, keyID)
		}
		for i := range m.iamKeys {
			if m.iamKeys[i].id == keyID {
				m.iamKeys[i].status = status
			}
		}
		_, _ = fmt.Fprint(w, `<UpdateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata></UpdateAccessKeyResponse>`)
	case "DeleteAccessKey":
		keyID := r.FormValue("AccessKeyId")
		m.deletedKeys = append(m.deletedKeys, keyID)
		var kept []mockIAMKey
		for _, k := range m.iamKeys {
			if k.id != keyID {
				kept = append(kept, k)
			}
		}
		m.iamKeys = kept
		_, _ = fmt.Fprint(w, `<DeleteAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>req-2</RequestId></ResponseMetadata></DeleteAccessKeyResponse>`)
	case "GetCallerIdentity":
		m.stsCalls++
		_, _ = fmt.Fprint(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/ci-deployer</Arn><UserId>AIDA1</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (m *mockBackend) handleGitHubREST(w http.ResponseWriter, r *http.Request) {
	pubB64 := base64.StdEncoding.EncodeToString(m.pubKey[:])
	recentTS := time.Now().UTC().Add(-3 * time.Hour).Format(time.RFC3339)

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/orgs/acme/repos":
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "api", "full_name": "acme/api", "default_branch": "main", "archived": false, "owner": map[string]string{"login": "acme"}},
			{"name": "web", "full_name": "acme/web", "default_branch": "main", "archived": false, "owner": map[string]string{"login": "acme"}},
			{"name": "legacy", "full_name": "acme/legacy", "default_branch": "main", "archived": true, "owner": map[string]string{"login": "acme"}},
		})
	case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api":
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "api", "full_name": "acme/api", "default_branch": "main", "owner": map[string]string{"login": "acme"}})
	case r.Method == http.MethodGet && r.URL.Path == "/orgs/acme/actions/secrets":
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "org secrets require admin"})
	case r.Method == http.MethodGet && (r.URL.Path == "/repos/acme/api/actions/secrets" || r.URL.Path == "/repos/acme/web/actions/secrets"):
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secrets": []map[string]any{
				{"name": "AWS_ACCESS_KEY_ID", "updated_at": "2026-01-01T00:00:00Z"},
				{"name": "AWS_SECRET_ACCESS_KEY", "updated_at": "2026-01-01T00:00:00Z"},
			},
		})
	case r.Method == http.MethodGet && (r.URL.Path == "/repos/acme/api/environments" || r.URL.Path == "/repos/acme/web/environments"):
		_ = json.NewEncoder(w).Encode(map[string]any{"environments": []any{}})
	case r.Method == http.MethodGet && (r.URL.Path == "/repos/acme/api/contents/.github/workflows" || r.URL.Path == "/repos/acme/web/contents/.github/workflows"):
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "deploy.yml", "path": ".github/workflows/deploy.yml", "type": "file"},
		})
	case r.Method == http.MethodGet && (r.URL.Path == "/repos/acme/api/contents/.github/workflows/deploy.yml" || r.URL.Path == "/repos/acme/web/contents/.github/workflows/deploy.yml"):
		_, _ = w.Write([]byte("on: pull_request_target\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo deploy\n        env:\n          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n"))
	case r.Method == http.MethodGet && (r.URL.Path == "/repos/acme/api/git/trees/main" || r.URL.Path == "/repos/acme/web/git/trees/main"):
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree": []map[string]any{{"path": "package-lock.json", "type": "blob"}},
		})
	case r.Method == http.MethodGet && (r.URL.Path == "/repos/acme/api/contents/package-lock.json" || r.URL.Path == "/repos/acme/web/contents/package-lock.json"):
		_, _ = w.Write([]byte(`{"lockfileVersion":3,"packages":{"node_modules/shai-hulud":{"version":"1.2.3"}}}`))
	case r.Method == http.MethodGet && (r.URL.Path == "/repos/acme/api/actions/runs" || r.URL.Path == "/repos/acme/web/actions/runs"):
		_ = json.NewEncoder(w).Encode(map[string]any{
			"workflow_runs": []map[string]any{
				{"id": 1001, "path": ".github/workflows/deploy.yml", "name": "Deploy", "event": "push", "created_at": recentTS},
			},
		})
	case r.Method == http.MethodGet && (r.URL.Path == "/repos/acme/api/actions/secrets/public-key" || r.URL.Path == "/repos/acme/web/actions/secrets/public-key"):
		_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "gh-pk-1", "key": pubB64})
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/repos/acme/"):
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/repos/"), "/")
		repoFull := parts[0] + "/" + parts[1]
		secretName := parts[len(parts)-1]

		m.mu.Lock()
		failRepo := m.failPutRepo
		m.mu.Unlock()
		if failRepo != "" && repoFull == failRepo {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "simulated GitHub failure"})
			return
		}

		var body struct {
			EncryptedValue string `json:"encrypted_value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cipherBytes, err := base64.StdEncoding.DecodeString(body.EncryptedValue)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		plain, ok := box.OpenAnonymous(nil, cipherBytes, m.pubKey, m.privKey)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		m.mu.Lock()
		m.putCalls++
		m.decryptedValues[repoFull+":"+secretName] = string(plain)
		m.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func buildRotexBinary(t *testing.T) string {
	t.Helper()
	binName := "rotex"
	if runtime.GOOS == "windows" {
		binName = "rotex.exe"
	}
	binPath := filepath.Join(t.TempDir(), binName)
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/rotex")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build rotex binary: %v\n%s", err, out)
	}
	return binPath
}

func runCLI(t *testing.T, binPath, mockURL string, extraEnv []string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	env := append(os.Environ(),
		"GITHUB_TOKEN=ghp_e2e_secret_pat_never_leak",
		"GITHUB_API_URL="+mockURL,
		"AWS_ACCESS_KEY_ID=AKIA_MOCK_CALLER",
		"AWS_SECRET_ACCESS_KEY=mockCallerSecretKeyNeverLeak",
		"AWS_REGION=us-east-1",
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_ENDPOINT_URL_IAM="+mockURL,
		"AWS_ENDPOINT_URL_STS="+mockURL,
		"AWS_ENDPOINT_URL_CLOUDTRAIL="+mockURL,
	)
	env = append(env, extraEnv...)
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	combined := stdout.String() + stderr.String()
	for _, secret := range []string{"ghp_e2e_secret_pat_never_leak", "mockCallerSecretKeyNeverLeak", "e2eSecretAccessKeyValueDoNotLeak"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("CLI output leaked secret %q!\nstdout:\n%s\nstderr:\n%s", secret, stdout.String(), stderr.String())
		}
	}
	return stdout.String(), stderr.String(), err
}

func TestRotexCLIEndToEnd(t *testing.T) {
	binPath := buildRotexBinary(t)
	backend := newMockBackend(t)
	srv := backend.server()
	defer srv.Close()

	// 1. Scan org with 403 graceful degradation + archived skip.
	stdout, stderr, err := runCLI(t, binPath, srv.URL, nil, "scan", "--org", "acme", "--format", "json")
	if err != nil {
		t.Fatalf("e2e scan failed: %v\nstderr: %s", err, stderr)
	}
	var scanRep model.ScanReport
	if err := json.Unmarshal([]byte(stdout), &scanRep); err != nil {
		t.Fatalf("decode scan JSON failed: %v\n%s", err, stdout)
	}
	if scanRep.Summary.ReposScanned != 2 || scanRep.Summary.ReposSkipped != 1 || scanRep.Summary.WarningsCount != 1 {
		t.Fatalf("unexpected scan summary: %+v", scanRep.Summary)
	}

	// 2. Scan single repo --with-aws (IAM + CloudTrail correlation).
	stdout, stderr, err = runCLI(t, binPath, srv.URL, nil, "scan", "--repo", "acme/api", "--with-aws", "--format", "json")
	if err != nil {
		t.Fatalf("e2e scan --with-aws failed: %v\nstderr: %s", err, stderr)
	}
	var awsRep model.ScanReport
	if err := json.Unmarshal([]byte(stdout), &awsRep); err != nil {
		t.Fatalf("decode scan --with-aws JSON failed: %v", err)
	}
	if len(awsRep.AWSKeys) != 1 || awsRep.AWSKeys[0].AccessKeyID != "AKIA_OLD_ACTIVE" || !awsRep.AWSKeys[0].GitHubRunnerSeen {
		t.Fatalf("unexpected AWS correlation: %+v", awsRep.AWSKeys)
	}

	// 3. Blast incident mode.
	stdout, stderr, err = runCLI(t, binPath, srv.URL, nil, "blast", "--org", "acme", "--pkg", "shai-hulud@1.2.3", "--format", "json")
	if err != nil {
		t.Fatalf("e2e blast failed: %v\nstderr: %s", err, stderr)
	}
	var blastRep model.BlastReport
	if err := json.Unmarshal([]byte(stdout), &blastRep); err != nil {
		t.Fatalf("decode blast JSON failed: %v", err)
	}
	if len(blastRep.Matches) != 2 || len(blastRep.RotationQueue) == 0 || blastRep.RotationQueue[0].Severity != "CRITICAL" {
		t.Fatalf("unexpected blast report: %+v", blastRep)
	}

	// 4. Rotate --dry-run (no mutations).
	stateDir := t.TempDir()
	stdout, stderr, err = runCLI(t, binPath, srv.URL, nil,
		"rotate", "--iam-user", "ci-deployer", "--repo", "acme/api", "--repo", "acme/web", "--dry-run", "--state-dir", stateDir, "--format", "json")
	if err != nil {
		t.Fatalf("e2e rotate --dry-run failed: %v\nstderr: %s", err, stderr)
	}
	snap := backend.snapshot()
	if snap.createCalls != 0 || snap.putCalls != 0 {
		t.Fatalf("dry-run must not mutate APIs")
	}

	// 5. Rotate --apply happy path + cleanup.
	stdout, stderr, err = runCLI(t, binPath, srv.URL, nil,
		"rotate", "--iam-user", "ci-deployer", "--repo", "acme/api", "--repo", "acme/web",
		"--apply", "--state-dir", stateDir, "--verify-timeout", "2s", "--verify-backoff", "10ms", "--format", "json")
	if err != nil {
		t.Fatalf("e2e rotate --apply failed: %v\nstderr: %s", err, stderr)
	}
	var runState rotate.RunState
	if err := json.Unmarshal([]byte(stdout), &runState); err != nil {
		t.Fatalf("decode rotate state JSON failed: %v\n%s", err, stdout)
	}
	if runState.Stage != rotate.StageCompleted || !runState.OldDeactivated || runState.NewKeyID != "AKIA_MINTED_NEW" {
		t.Fatalf("unexpected rotate state: %+v", runState)
	}
	snap = backend.snapshot()
	if snap.stsCalls == 0 || snap.decryptedValues["acme/web:AWS_SECRET_ACCESS_KEY"] != "e2eSecretAccessKeyValueDoNotLeak" {
		t.Fatalf("expected STS verify and sealed box decryption match, sts=%d", snap.stsCalls)
	}
	rawJournal, err := os.ReadFile(filepath.Join(stateDir, runState.RunID+".json"))
	if err != nil || strings.Contains(string(rawJournal), "e2eSecretAccessKeyValueDoNotLeak") {
		t.Fatalf("journal missing or leaked secret: err=%v", err)
	}

	// Cleanup old key.
	stdout, stderr, err = runCLI(t, binPath, srv.URL, nil, "cleanup", "--run-id", runState.RunID, "--state-dir", stateDir, "--format", "json")
	if err != nil {
		t.Fatalf("e2e cleanup failed: %v\nstderr: %s", err, stderr)
	}
	var cleaned rotate.RunState
	if err := json.Unmarshal([]byte(stdout), &cleaned); err != nil || cleaned.Stage != rotate.StageRevoked {
		t.Fatalf("expected REVOKED after cleanup, got: %+v", cleaned)
	}

	// 6. Mid-flight partial injection failure preserves BOTH old and new active keys to avoid breaking updated repos.
	backend.reset("acme/web", mockIAMKey{id: "AKIA_OLD_ACTIVE", status: "Active"})

	stdout, _, err = runCLI(t, binPath, srv.URL, nil,
		"rotate", "--iam-user", "ci-deployer", "--repo", "acme/api", "--repo", "acme/web",
		"--apply", "--state-dir", stateDir, "--verify-timeout", "2s", "--verify-backoff", "10ms", "--format", "json")
	if err == nil {
		t.Fatalf("expected rotate --apply to fail when acme/web returns HTTP 500")
	}
	var partialState rotate.RunState
	if err := json.Unmarshal([]byte(stdout), &partialState); err != nil {
		t.Fatalf("decode failed state JSON: %v\n%s", err, stdout)
	}
	if partialState.Stage != rotate.StageFailedRecoverable || partialState.NewDeleted || partialState.OldDeactivated {
		t.Fatalf("expected partial failure to keep both keys active in FAILED_RECOVERABLE, got: %+v", partialState)
	}
	snap = backend.snapshot()
	if len(snap.deactivatedKeys) != 0 || len(snap.deletedKeys) != 0 {
		t.Fatalf("neither key must be deactivated or deleted after partial injection: deactivated=%v deleted=%v", snap.deactivatedKeys, snap.deletedKeys)
	}

	// Clean up minted key before testing 2-key guard cleanly.
	_, _, err = runCLI(t, binPath, srv.URL, nil,
		"rollback", "--run-id", partialState.RunID, "--state-dir", stateDir, "--format", "json")
	if err != nil {
		t.Fatalf("cleanup rollback after partial failure failed: %v", err)
	}

	// 6b. Pre-mutation injection failure (first target fails) triggers automatic rollback deleting NewKeyID.
	backend.reset("acme/api", mockIAMKey{id: "AKIA_OLD_ACTIVE", status: "Active"})

	stdout, _, err = runCLI(t, binPath, srv.URL, nil,
		"rotate", "--iam-user", "ci-deployer", "--repo", "acme/api", "--repo", "acme/web",
		"--apply", "--state-dir", stateDir, "--verify-timeout", "2s", "--verify-backoff", "10ms", "--format", "json")
	if err == nil {
		t.Fatalf("expected rotate --apply to fail when first repo acme/api returns HTTP 500")
	}
	var rolledState rotate.RunState
	if err := json.Unmarshal([]byte(stdout), &rolledState); err != nil {
		t.Fatalf("decode failed state JSON: %v\n%s", err, stdout)
	}
	if rolledState.Stage != rotate.StageRolledBack || !rolledState.NewDeleted {
		t.Fatalf("expected automatic rollback to ROLLED_BACK when 0 secrets were mutated, got: %+v", rolledState)
	}
	snap = backend.snapshot()
	if len(snap.deactivatedKeys) != 0 {
		t.Fatalf("old key must not be deactivated on failed injection: %v", snap.deactivatedKeys)
	}

	// 7. 2-key AWS quota guard aborts before minting.
	prevCreate := backend.reset("",
		mockIAMKey{id: "AKIA_1", status: "Active"},
		mockIAMKey{id: "AKIA_2", status: "Inactive"},
	)

	_, stderr, err = runCLI(t, binPath, srv.URL, nil,
		"rotate", "--iam-user", "ci-deployer", "--repo", "acme/api", "--apply", "--state-dir", stateDir)
	if err == nil || !strings.Contains(stderr, "2/2") {
		t.Fatalf("expected 2/2 quota error on stderr, got err=%v stderr=%s", err, stderr)
	}
	if snap := backend.snapshot(); snap.createCalls != prevCreate {
		t.Fatalf("2-key guard must abort before calling CreateAccessKey")
	}

	// 8. Manual rollback on a completed run restores old key and deletes new key.
	backend.reset("", mockIAMKey{id: "AKIA_OLD_ACTIVE", status: "Active"})

	stdout, stderr, err = runCLI(t, binPath, srv.URL, nil,
		"rotate", "--iam-user", "ci-deployer", "--repo", "acme/api",
		"--apply", "--state-dir", stateDir, "--verify-timeout", "2s", "--verify-backoff", "10ms", "--format", "json")
	if err != nil {
		t.Fatalf("e2e rotate for rollback test failed: %v\nstderr: %s", err, stderr)
	}
	var completedForRollback rotate.RunState
	if err := json.Unmarshal([]byte(stdout), &completedForRollback); err != nil {
		t.Fatalf("decode rotate state failed: %v", err)
	}

	stdout, stderr, err = runCLI(t, binPath, srv.URL, nil,
		"rollback", "--run-id", completedForRollback.RunID, "--state-dir", stateDir, "--format", "json")
	if err != nil {
		t.Fatalf("e2e manual rollback failed: %v\nstderr: %s", err, stderr)
	}
	var manualRolled rotate.RunState
	if err := json.Unmarshal([]byte(stdout), &manualRolled); err != nil {
		t.Fatalf("decode manual rollback JSON failed: %v", err)
	}
	if manualRolled.Stage != rotate.StageRolledBack || manualRolled.OldDeactivated || !manualRolled.NewDeleted {
		t.Fatalf("unexpected manual rollback state: %+v", manualRolled)
	}
}
