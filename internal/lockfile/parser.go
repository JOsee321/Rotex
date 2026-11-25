package lockfile

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	pathpkg "path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Ecosystem identifies a package ecosystem inferred from a lockfile.
type Ecosystem string

const (
	EcosystemNPM  Ecosystem = "npm"
	EcosystemGo   Ecosystem = "go"
	EcosystemPyPI Ecosystem = "pypi"
)

// Dependency represents a single resolved package entry parsed from a lockfile.
type Dependency struct {
	Ecosystem Ecosystem `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Lockfile  string    `json:"lockfile"`
}

// PackageSpec identifies a compromised package target (optional version).
type PackageSpec struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// SupportedFilenames lists lockfile basenames recognized by IsLockfile.
var SupportedFilenames = []string{
	"package-lock.json",
	"pnpm-lock.yaml",
	"yarn.lock",
	"go.sum",
	"requirements.txt",
	"poetry.lock",
}

// IsLockfile reports whether path refers to a supported dependency lockfile.
func IsLockfile(p string) bool {
	base := strings.ToLower(pathpkg.Base(strings.ReplaceAll(p, "\\", "/")))
	return slices.Contains(SupportedFilenames, base)
}

// Parse extracts resolved dependencies from a supported lockfile.
func Parse(path string, content []byte) ([]Dependency, error) {
	base := strings.ToLower(pathpkg.Base(strings.ReplaceAll(path, "\\", "/")))
	switch base {
	case "package-lock.json":
		return parsePackageLock(path, content)
	case "pnpm-lock.yaml":
		return parsePnpmLock(path, content)
	case "yarn.lock":
		return parseYarnLock(path, content)
	case "go.sum":
		return parseGoSum(path, content)
	case "requirements.txt":
		return parseRequirementsTxt(path, content)
	case "poetry.lock":
		return parsePoetryLock(path, content)
	default:
		return nil, fmt.Errorf("unsupported lockfile %q", path)
	}
}

// ParsePackageSpec parses strings such as "pkg@1.2.3", "@scope/pkg@1.2.3", or "pkg".
func ParsePackageSpec(raw string) (PackageSpec, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return PackageSpec{}, fmt.Errorf("package spec must not be empty")
	}
	at := strings.LastIndex(s, "@")
	if at > 0 {
		name := strings.TrimSpace(s[:at])
		ver := strings.TrimSpace(s[at+1:])
		if name == "" || ver == "" {
			return PackageSpec{}, fmt.Errorf("invalid package spec %q", raw)
		}
		return PackageSpec{Name: name, Version: ver}, nil
	}
	return PackageSpec{Name: s}, nil
}

// ParseAdvisoryJSON extracts package targets from OSV JSON or a simple JSON package list.
func ParseAdvisoryJSON(data []byte) ([]PackageSpec, error) {
	var osv struct {
		Affected []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Versions []string `json:"versions"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(data, &osv); err == nil && len(osv.Affected) > 0 {
		var specs []PackageSpec
		for _, aff := range osv.Affected {
			name := strings.TrimSpace(aff.Package.Name)
			if name == "" {
				continue
			}
			if len(aff.Versions) == 0 {
				specs = append(specs, PackageSpec{Name: name})
				continue
			}
			for _, v := range aff.Versions {
				specs = append(specs, PackageSpec{Name: name, Version: strings.TrimSpace(v)})
			}
		}
		if len(specs) > 0 {
			return deduplicateSpecs(specs), nil
		}
	}

	var list []PackageSpec
	if err := json.Unmarshal(data, &list); err == nil && len(list) > 0 {
		var valid []PackageSpec
		for _, item := range list {
			if strings.TrimSpace(item.Name) != "" {
				valid = append(valid, PackageSpec{
					Name:    strings.TrimSpace(item.Name),
					Version: strings.TrimSpace(item.Version),
				})
			}
		}
		if len(valid) > 0 {
			return deduplicateSpecs(valid), nil
		}
	}

	return nil, fmt.Errorf("unrecognized advisory JSON format")
}

// Match filters deps that match any target in specs.
func Match(deps []Dependency, specs []PackageSpec) []Dependency {
	var matched []Dependency
	for _, dep := range deps {
		for _, spec := range specs {
			if !strings.EqualFold(dep.Name, spec.Name) {
				continue
			}
			if spec.Version == "" || versionsEqual(dep.Version, spec.Version) {
				matched = append(matched, dep)
				break
			}
		}
	}
	return matched
}

func versionsEqual(a, b string) bool {
	if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) {
		return true
	}
	return strings.TrimPrefix(strings.TrimSpace(a), "v") == strings.TrimPrefix(strings.TrimSpace(b), "v")
}

func parsePackageLock(path string, content []byte) ([]Dependency, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, nil
	}
	var doc struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]packageLockDep `json:"dependencies"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var out []Dependency
	seen := make(map[string]struct{})
	add := func(name, ver string) {
		if name == "" || ver == "" {
			return
		}
		key := name + "@" + ver
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Dependency{Ecosystem: EcosystemNPM, Name: name, Version: ver, Lockfile: path})
	}

	for pkgPath, pkg := range doc.Packages {
		if pkgPath == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = extractNodeModulesPkgName(pkgPath)
		}
		add(name, pkg.Version)
	}

	var walkDeps func(m map[string]packageLockDep)
	walkDeps = func(m map[string]packageLockDep) {
		for name, info := range m {
			add(name, info.Version)
			if len(info.Dependencies) > 0 {
				walkDeps(info.Dependencies)
			}
		}
	}
	walkDeps(doc.Dependencies)

	return out, nil
}

type packageLockDep struct {
	Version      string                    `json:"version"`
	Dependencies map[string]packageLockDep `json:"dependencies"`
}

func extractNodeModulesPkgName(pkgPath string) string {
	idx := strings.LastIndex(pkgPath, "node_modules/")
	if idx == -1 {
		return ""
	}
	return pkgPath[idx+len("node_modules/"):]
}

func parsePnpmLock(path string, content []byte) ([]Dependency, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, nil
	}
	var doc struct {
		Packages map[string]any `yaml:"packages"`
	}
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var out []Dependency
	seen := make(map[string]struct{})
	for rawKey := range doc.Packages {
		name, ver := parsePnpmPackageKey(rawKey)
		if name == "" || ver == "" {
			continue
		}
		id := name + "@" + ver
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, Dependency{Ecosystem: EcosystemNPM, Name: name, Version: ver, Lockfile: path})
	}
	return out, nil
}

func parsePnpmPackageKey(raw string) (string, string) {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "/")
	if idx := strings.Index(s, "("); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "_"); idx != -1 && !strings.Contains(s[:idx], "@") {
		// Ignore unrelated suffix patterns if not scoped.
	}
	// pnpm v6/v9 uses "pkg@1.2.3" or "@scope/pkg@1.2.3"; pnpm v5 uses "pkg/1.2.3" or "@scope/pkg/1.2.3".
	if at := strings.LastIndex(s, "@"); at > 0 {
		return s[:at], s[at+1:]
	}
	if slash := strings.LastIndex(s, "/"); slash > 0 {
		return s[:slash], s[slash+1:]
	}
	return "", ""
}

func parseYarnLock(path string, content []byte) ([]Dependency, error) {
	var out []Dependency
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(content))

	var currentNames []string
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "__metadata") {
			continue
		}

		// Top-level header lines are unindented and end with ':'.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			header := strings.TrimSuffix(trimmed, ":")
			currentNames = parseYarnHeaderNames(header)
			continue
		}

		if len(currentNames) > 0 && (strings.HasPrefix(trimmed, "version ") || strings.HasPrefix(trimmed, "version:")) {
			ver := strings.TrimPrefix(trimmed, "version:")
			ver = strings.TrimPrefix(ver, "version ")
			ver = strings.Trim(strings.TrimSpace(ver), `"'`)
			if ver != "" {
				for _, name := range currentNames {
					key := name + "@" + ver
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					out = append(out, Dependency{Ecosystem: EcosystemNPM, Name: name, Version: ver, Lockfile: path})
				}
			}
			currentNames = nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

func parseYarnHeaderNames(header string) []string {
	parts := strings.Split(header, ",")
	var names []string
	for _, p := range parts {
		spec := strings.Trim(strings.TrimSpace(p), `"'`)
		if spec == "" {
			continue
		}
		at := strings.LastIndex(spec, "@")
		if at > 0 {
			name := spec[:at]
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}

func parseGoSum(path string, content []byte) ([]Dependency, error) {
	var out []Dependency
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		ver := strings.TrimSuffix(fields[1], "/go.mod")
		key := name + "@" + ver
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Dependency{Ecosystem: EcosystemGo, Name: name, Version: ver, Lockfile: path})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

func parseRequirementsTxt(path string, content []byte) ([]Dependency, error) {
	var out []Dependency
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, ";"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		name, ver := splitRequirement(line)
		if name == "" {
			continue
		}
		key := name + "@" + ver
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Dependency{Ecosystem: EcosystemPyPI, Name: name, Version: ver, Lockfile: path})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

func splitRequirement(line string) (string, string) {
	for _, op := range []string{"===", "==", "~=", ">=", "<=", "!="} {
		if idx := strings.Index(line, op); idx != -1 {
			name := strings.TrimSpace(line[:idx])
			if br := strings.Index(name, "["); br != -1 {
				name = name[:br]
			}
			ver := strings.TrimSpace(line[idx+len(op):])
			return name, ver
		}
	}
	if br := strings.Index(line, "["); br != -1 {
		return strings.TrimSpace(line[:br]), ""
	}
	return strings.TrimSpace(line), ""
}

func parsePoetryLock(path string, content []byte) ([]Dependency, error) {
	var out []Dependency
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(content))
	var inPkg bool
	var curName, curVer string

	flush := func() {
		if curName != "" && curVer != "" {
			key := curName + "@" + curVer
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				out = append(out, Dependency{Ecosystem: EcosystemPyPI, Name: curName, Version: curVer, Lockfile: path})
			}
		}
		curName = ""
		curVer = ""
	}

	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "[[package]]" {
			flush()
			inPkg = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") && trimmed != "[[package]]" {
			flush()
			inPkg = false
			continue
		}
		if !inPkg {
			continue
		}
		if k, v, ok := strings.Cut(trimmed, "="); ok {
			key := strings.TrimSpace(k)
			val := strings.Trim(strings.TrimSpace(v), `"'`)
			switch key {
			case "name":
				curName = val
			case "version":
				curVer = val
			}
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

func deduplicateSpecs(specs []PackageSpec) []PackageSpec {
	seen := make(map[string]struct{}, len(specs))
	var out []PackageSpec
	for _, s := range specs {
		key := strings.ToLower(s.Name) + "@" + s.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out
}
