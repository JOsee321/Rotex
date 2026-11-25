package lockfile

import "testing"

func TestIsLockfile(t *testing.T) {
	for _, yes := range []string{
		"package-lock.json",
		"apps/web/pnpm-lock.yaml",
		"yarn.lock",
		"go.sum",
		"requirements.txt",
		"poetry.lock",
	} {
		if !IsLockfile(yes) {
			t.Errorf("expected IsLockfile(%q) = true", yes)
		}
	}
	for _, no := range []string{"package.json", "go.mod", "README.md"} {
		if IsLockfile(no) {
			t.Errorf("expected IsLockfile(%q) = false", no)
		}
	}
}

func TestParseAndMatchAllLockfiles(t *testing.T) {
	npmLock := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0"},
	    "node_modules/evil-pkg": {"version": "1.2.3"},
	    "node_modules/@acme/core": {"version": "2.0.1"}
	  }
	}`)
	deps, err := Parse("package-lock.json", npmLock)
	if err != nil {
		t.Fatalf("parse package-lock.json failed: %v", err)
	}
	spec, _ := ParsePackageSpec("evil-pkg@1.2.3")
	if matched := Match(deps, []PackageSpec{spec}); len(matched) != 1 {
		t.Fatalf("expected evil-pkg match, got %+v", matched)
	}

	pnpmLock := []byte(`
lockfileVersion: '9.0'
packages:
  'evil-pkg@1.2.3':
    resolution: {integrity: sha512-abc}
  '/@scope/lib@3.1.0(react@18.0.0)':
    resolution: {integrity: sha512-def}
`)
	pnpmDeps, err := Parse("pnpm-lock.yaml", pnpmLock)
	if err != nil || len(pnpmDeps) != 2 {
		t.Fatalf("parse pnpm-lock.yaml failed: %v, deps=%+v", err, pnpmDeps)
	}
	scopeSpec, _ := ParsePackageSpec("@scope/lib@3.1.0")
	if matched := Match(pnpmDeps, []PackageSpec{scopeSpec}); len(matched) != 1 {
		t.Fatalf("expected @scope/lib match in pnpm-lock.yaml, got %+v", matched)
	}

	yarnLock := []byte(`
# yarn lockfile v1
"evil-pkg@^1.2.0", "evil-pkg@1.2.3":
  version "1.2.3"

"@scope/lib@npm:^3.0.0":
  version: 3.1.0
`)
	yarnDeps, err := Parse("yarn.lock", yarnLock)
	if err != nil || len(yarnDeps) != 2 {
		t.Fatalf("parse yarn.lock failed: %v, deps=%+v", err, yarnDeps)
	}

	goSum := []byte(`
github.com/evil/mod v1.4.2 h1:abc=
github.com/evil/mod v1.4.2/go.mod h1:def=
`)
	goDeps, err := Parse("go.sum", goSum)
	if err != nil || len(goDeps) != 1 {
		t.Fatalf("parse go.sum failed: %v, deps=%+v", err, goDeps)
	}
	goSpec, _ := ParsePackageSpec("github.com/evil/mod@1.4.2")
	if matched := Match(goDeps, []PackageSpec{goSpec}); len(matched) != 1 {
		t.Fatalf("expected go.sum v-prefix tolerant match, got %+v", matched)
	}

	reqTxt := []byte("requests==2.32.0 # comment\nurllib3>=2.0.0; python_version >= '3.8'\n")
	reqDeps, err := Parse("requirements.txt", reqTxt)
	if err != nil || len(reqDeps) != 2 {
		t.Fatalf("parse requirements.txt failed: %v, deps=%+v", err, reqDeps)
	}

	poetryLock := []byte("[[package]]\nname = \"requests\"\nversion = \"2.32.0\"\n")
	poetryDeps, err := Parse("poetry.lock", poetryLock)
	if err != nil || len(poetryDeps) != 1 {
		t.Fatalf("parse poetry.lock failed: %v, deps=%+v", err, poetryDeps)
	}
}

func TestParseAdvisoryJSON(t *testing.T) {
	osv := []byte(`{
	  "id": "GHSA-xxxx",
	  "affected": [
	    {"package": {"name": "shai-hulud", "ecosystem": "npm"}, "versions": ["1.0.1", "1.0.2"]}
	  ]
	}`)
	specs, err := ParseAdvisoryJSON(osv)
	if err != nil || len(specs) != 2 {
		t.Fatalf("ParseAdvisoryJSON OSV failed: %v, specs=%+v", err, specs)
	}
}
