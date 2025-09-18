package javascript

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parsePackageJSON

// packageJSON represents a JavaScript package.json file
type packageJSON struct {
	Version         string            `json:"version"`
	Latest          []string          `json:"latest"`
	Author          author            `json:"author"`
	License         json.RawMessage   `json:"license"`
	Licenses        json.RawMessage   `json:"licenses"`
	Name            string            `json:"name"`
	Homepage        string            `json:"homepage"`
	Description     string            `json:"description"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Repository      repository        `json:"repository"`
	Private         bool              `json:"private"`
}

type author struct {
	Name  string `json:"name" mapstruct:"name"`
	Email string `json:"email" mapstruct:"email"`
	URL   string `json:"url" mapstruct:"url"`
}

type repository struct {
	Type string `json:"type" mapstructure:"type"`
	URL  string `json:"url" mapstructure:"url"`
}

// match example: "author": "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)"
// ---> name: "Isaac Z. Schlueter" email: "i@izs.me" url: "http://blog.izs.me"
var authorPattern = regexp.MustCompile(`^\s*(?P<name>[^<(]*)(\s+<(?P<email>.*)>)?(\s\((?P<url>.*)\))?\s*$`)


// parsePackageJSON parses a package.json and returns the discovered JavaScript packages.
func parsePackageJSON(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	dec := json.NewDecoder(reader)

	for {
		var p packageJSON
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse package.json file: %w", err)
		}

		// always create a package, regardless of having a valid name and/or version,
		// a compliance filter later will remove these packages based on compliance rules
		pkgs = append(
			pkgs,
			newPackageJSONPackage(p, reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		)

		// Check if this package.json is from a bundler's dist directory and update missing versions
		updateVersionsFromBundlerDevDependencies(p, reader.Location, resolver, pkgs)
	}

	pkg.Sort(pkgs)

	return pkgs, nil, nil
}

func (a *author) UnmarshalJSON(b []byte) error {
	var authorStr string
	var auth author

	if err := json.Unmarshal(b, &authorStr); err == nil {
		// successfully parsed as a string, now parse that string into fields
		fields := internal.MatchNamedCaptureGroups(authorPattern, authorStr)
		if err := mapstructure.Decode(fields, &auth); err != nil {
			return fmt.Errorf("unable to decode package.json author: %w", err)
		}
	} else {
		// it's a map that may contain fields of various data types (not just strings)
		var fields map[string]interface{}
		if err := json.Unmarshal(b, &fields); err != nil {
			return fmt.Errorf("unable to parse package.json author: %w", err)
		}
		if err := mapstructure.Decode(fields, &auth); err != nil {
			return fmt.Errorf("unable to decode package.json author: %w", err)
		}
	}

	*a = auth

	return nil
}

func (a *author) AuthorString() string {
	result := a.Name
	if a.Email != "" {
		result += fmt.Sprintf(" <%s>", a.Email)
	}
	if a.URL != "" {
		result += fmt.Sprintf(" (%s)", a.URL)
	}
	return result
}

func (r *repository) UnmarshalJSON(b []byte) error {
	var repositoryStr string
	var fields map[string]string
	var repo repository

	if err := json.Unmarshal(b, &repositoryStr); err != nil {
		// string parsing did not work, assume a map was given
		// for more information: https://docs.npmjs.com/files/package.json#people-fields-author-contributors
		if err := json.Unmarshal(b, &fields); err != nil {
			return fmt.Errorf("unable to parse package.json author: %w", err)
		}
		// translate the map into a structure
		if err := mapstructure.Decode(fields, &repo); err != nil {
			return fmt.Errorf("unable to decode package.json author: %w", err)
		}

		*r = repo
	} else {
		r.URL = repositoryStr
	}

	return nil
}

type npmPackageLicense struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func licenseFromJSON(b []byte) (string, error) {
	// first try as string
	var licenseString string
	err := json.Unmarshal(b, &licenseString)
	if err == nil {
		return licenseString, nil
	}

	// then try as object (this format is deprecated)
	var licenseObject npmPackageLicense
	err = json.Unmarshal(b, &licenseObject)
	if err == nil {
		return licenseObject.Type, nil
	}

	return "", errors.New("unable to unmarshal license field as either string or object")
}

func (p packageJSON) licensesFromJSON() ([]string, error) {
	if p.License == nil && p.Licenses == nil {
		// This package.json doesn't specify any licenses whatsoever
		return []string{}, nil
	}

	singleLicense, err := licenseFromJSON(p.License)
	if err == nil {
		return []string{singleLicense}, nil
	}

	multiLicense, err := licensesFromJSON(p.Licenses)

	// The "licenses" field is deprecated. It should be inspected as a last resort.
	if multiLicense != nil && err == nil {
		mapLicenses := func(licenses []npmPackageLicense) []string {
			mappedLicenses := make([]string, len(licenses))
			for i, l := range licenses {
				mappedLicenses[i] = l.Type
			}
			return mappedLicenses
		}

		return mapLicenses(multiLicense), nil
	}

	return nil, err
}

func licensesFromJSON(b []byte) ([]npmPackageLicense, error) {
	var licenseObject []npmPackageLicense
	err := json.Unmarshal(b, &licenseObject)
	if err == nil {
		return licenseObject, nil
	}

	return nil, errors.New("unmarshal failed")
}


func pathContainsNodeModulesDirectory(p string) bool {
	// Normalize path to use forward slashes and split by filepath separator
	p = filepath.ToSlash(p)
	parts := strings.Split(p, "/")
	for _, part := range parts {
		if part == "node_modules" {
			return true
		}
	}
	return false
}

// updateVersionsFromBundlerDevDependencies checks if this package.json is from a bundler's dist directory
// and if so, updates the version of the current package from the parent package.json devDependencies
func updateVersionsFromBundlerDevDependencies(p packageJSON, location file.Location, resolver file.Resolver, existingPkgs []pkg.Package) {
	if p.Version != "" {
		return
	}

	bundlerName, parentPackageJSONPath := parseBundlerPath(location.RealPath)
	if bundlerName == "" {
		return
	}

	parentPackageJSON := loadPackageJSON(parentPackageJSONPath, resolver)
	if parentPackageJSON == nil {
		return
	}

	// Look for the current package in the parent's devDependencies or npm aliases
	if version, exists := parentPackageJSON.DevDependencies[p.Name]; exists && version != "" {
		if len(existingPkgs) > 0 {
			lastPkg := &existingPkgs[len(existingPkgs)-1]
			if lastPkg.Name == p.Name && lastPkg.Version == "" {
				lastPkg.Version = version
				lastPkg.PURL = packageURL(p.Name, version)

				if npmMeta, ok := lastPkg.Metadata.(pkg.NpmPackage); ok {
					npmMeta.Version = version
					lastPkg.Metadata = npmMeta
				}
			}
		}
	}
}

// parseBundlerPath checks if the path is in a bundler's dist directory and returns bundler name + parent package.json path
// Returns empty bundler name if not a bundler dist path
func parseBundlerPath(path string) (bundlerName, parentPackageJSONPath string) {
	// Clean the path and split using the OS-specific separator
	cleanPath := filepath.Clean(path)
	pathParts := strings.Split(cleanPath, string(filepath.Separator))

	// Look for: node_modules/{bundler}/dist/...
	for i, part := range pathParts {
		if part == "node_modules" && i+2 < len(pathParts) {
			bundler := pathParts[i+1]
			distDir := pathParts[i+2]

			// Check for supported bundlers with dist directories
			if (bundler == "next" || bundler == "vite") && distDir == "dist" {
				// Build parent package.json path: node_modules/{bundler}/package.json
				parentParts := pathParts[:i+2] // Include up to bundler directory
				parentParts = append(parentParts, "package.json")
				parentPath := strings.Join(parentParts, string(filepath.Separator))
				return bundler, parentPath
			}
		}
	}
	return "", ""
}

// loadPackageJSON reads and parses a package.json file using the same logic as the main parser
func loadPackageJSON(packageJSONPath string, resolver file.Resolver) *packageJSON {
	locations, err := resolver.FilesByPath(packageJSONPath)
	if err != nil || len(locations) == 0 {
		return nil
	}

	contentReader, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return nil
	}
	defer contentReader.Close()

	// Use the same JSON decoder approach as the main parsePackageJSON function
	dec := json.NewDecoder(contentReader)
	var pkg packageJSON
	if err := dec.Decode(&pkg); err != nil {
		return nil
	}

	return &pkg
}
