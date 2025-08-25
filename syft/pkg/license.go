package pkg

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
)

var _ sort.Interface = (*Licenses)(nil)

// License represents an SPDX Expression or license value extracted from a packages metadata
// We want to ignore URLs and Location since we merge these fields across equal licenses.
// A License is a unique combination of value, expression and type, where
// its sources are always considered merged and additions to the evidence
// of where it was found and how it was sourced.
// This is different from how we treat a package since we consider package paths
// in order to distinguish if packages should be kept separate
// this is different for licenses since we're only looking for evidence
// of where a license was declared/concluded for a given package
type License struct {
	Value          string
	SPDXExpression string
	Type           license.Type
	URLs           []string         `hash:"ignore"`
	Locations      file.LocationSet `hash:"ignore"`
}

type Licenses []License

func (l Licenses) Len() int {
	return len(l)
}

func (l Licenses) Less(i, j int) bool {
	if l[i].Value == l[j].Value {
		if l[i].SPDXExpression == l[j].SPDXExpression {
			if l[i].Type == l[j].Type {
				// While URLs and location are not exclusive fields
				// returning true here reduces the number of swaps
				// while keeping a consistent sort order of
				// the order that they appear in the list initially
				// If users in the future have preference to sorting based
				// on the slice representation of either field we can update this code
				return true
			}
			return l[i].Type < l[j].Type
		}
		return l[i].SPDXExpression < l[j].SPDXExpression
	}
	return l[i].Value < l[j].Value
}

func (l Licenses) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

func NewLicense(value string) License {
	return NewLicenseFromType(value, license.Declared)
}

func NewLicenseFromType(value string, t license.Type) License {
	var spdxExpression string
	if value != "" {
		var err error
		spdxExpression, err = license.ParseExpression(value)
		if err != nil {
			log.WithFields("error", err, "expression", value).Trace("unable to parse license expression")
		}
	}

	return License{
		Value:          value,
		SPDXExpression: spdxExpression,
		Type:           t,
		Locations:      file.NewLocationSet(),
	}
}

func NewLicensesFromValues(values ...string) (licenses []License) {
	for _, v := range values {
		licenses = append(licenses, NewLicense(v))
	}
	return
}

func NewLicensesFromLocation(location file.Location, values ...string) (licenses []License) {
	for _, v := range values {
		if v == "" {
			continue
		}
		licenses = append(licenses, NewLicenseFromLocations(v, location))
	}
	return
}

func NewLicenseFromLocations(value string, locations ...file.Location) License {
	l := NewLicense(value)
	for _, loc := range locations {
		l.Locations.Add(loc)
	}
	return l
}

func NewLicenseFromURLs(value string, urls ...string) License {
	l := NewLicense(value)
	s := strset.New()
	for _, url := range urls {
		if url != "" {
			sanitizedURL, err := stripUnwantedCharacters(url)
			if err != nil {
				log.Tracef("unable to sanitize url=%q: %s", url, err)
				continue
			}
			s.Add(sanitizedURL)
		}
	}

	l.URLs = s.List()
	sort.Strings(l.URLs)

	return l
}

func stripUnwantedCharacters(rawURL string) (string, error) {
	cleanedURL := strings.TrimSpace(rawURL)
	_, err := url.ParseRequestURI(cleanedURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	return cleanedURL, nil
}

func NewLicenseFromFields(value, url string, location *file.Location) License {
	l := NewLicense(value)
	if location != nil {
		l.Locations.Add(*location)
	}
	if url != "" {
		sanitizedURL, err := stripUnwantedCharacters(url)
		if err != nil {
			log.Tracef("unable to sanitize url=%q: %s", url, err)
		} else {
			l.URLs = append(l.URLs, sanitizedURL)
		}
	}

	return l
}

// Merge two licenses into a new license object. If the merge is not possible due to unmergeable fields
// (e.g. different values for Value, SPDXExpression, Type, or any non-collection type) an error is returned.
// TODO: this is a bit of a hack to not infinitely recurse when hashing a license
func (s License) Merge(l License) (*License, error) {
	sHash, err := artifact.IDByHash(s)
	if err != nil {
		return nil, err
	}
	lHash, err := artifact.IDByHash(l)
	if err != nil {
		return nil, err
	}
	if sHash != lHash {
		return nil, fmt.Errorf("cannot merge licenses with different hash")
	}

	// try to keep s.URLs unallocated unless necessary (which is the default state from the constructor)
	if len(l.URLs) > 0 {
		s.URLs = append(s.URLs, l.URLs...)
	}

	if len(s.URLs) > 0 {
		s.URLs = strset.New(s.URLs...).List()
		sort.Strings(s.URLs)
	}

	if l.Locations.Empty() {
		return &s, nil
	}

	// since the set instance has a reference type (map) we must make a new instance
	locations := file.NewLocationSet(s.Locations.ToSlice()...)
	locations.Add(l.Locations.ToSlice()...)
	s.Locations = locations

	return &s, nil
}

type licenseBuilder struct {
	values    []string
	contents  []io.ReadCloser
	locations []file.Location
	urls      []string
	tp        license.Type
}

func newLicenseBuilder() *licenseBuilder {
	return &licenseBuilder{
		tp: license.Declared,
	}
}

func (b *licenseBuilder) WithValues(expr ...string) *licenseBuilder {
	for _, v := range expr {
		if v == "" {
			continue
		}
		b.values = append(b.values, v)
	}
	return b
}

func (b *licenseBuilder) WithOptionalLocation(location *file.Location) *licenseBuilder {
	if location != nil {
		b.locations = append(b.locations, *location)
	}
	return b
}

func (b *licenseBuilder) WithURLs(urls ...string) *licenseBuilder {
	s := strset.New()
	for _, u := range urls {
		if u != "" {
			sanitizedURL, err := stripUnwantedCharacters(u)
			if err != nil {
				log.Tracef("unable to sanitize url=%q: %s", u, err)
				continue
			}
			s.Add(sanitizedURL)
		}
	}

	b.urls = append(b.urls, s.List()...)
	sort.Strings(b.urls)
	return b
}

func (b *licenseBuilder) WithLocations(locations ...file.Location) *licenseBuilder {
	for _, loc := range locations {
		if loc.Path() != "" {
			b.locations = append(b.locations, loc)
		}
	}
	return b
}

func (b *licenseBuilder) WithContents(contents ...io.ReadCloser) *licenseBuilder {
	for _, content := range contents {
		if content != nil {
			b.contents = append(b.contents, content)
		}
	}
	return b
}

func (b *licenseBuilder) WithType(t license.Type) *licenseBuilder {
	b.tp = t // last one wins, multiple is not valid
	return b
}

func (b *licenseBuilder) Build(ctx context.Context) LicenseSet {
	// for every value make a license with all locations
	// or for every reader make a license with all locations
	// if given a reader and a value, this is invalid

	locations := file.NewLocationSet(b.locations...)

	set := NewLicenseSet()
	for _, v := range b.values {
		if strings.Contains(v, "\n") {
			var loc file.Location
			if len(b.locations) > 0 {
				loc = b.locations[0]
			}
			b.contents = append(b.contents, file.NewLocationReadCloser(loc, io.NopCloser(strings.NewReader(v))))
			continue
		}

		// we want to check if the SPDX field should be set
		var expression string
		if ex, err := license.ParseExpression(v); err == nil {
			expression = ex
		}

		// Check if we should populate URLs from SPDX database
		urls := b.urls
		if len(urls) == 0 && expression != "" {
			if spdxURLs, found := spdxlicense.URLs(expression); found {
				urls = spdxURLs
			}
		}

		set.Add(License{
			SPDXExpression: expression,
			Value:          strings.TrimSpace(v),
			Type:           b.tp,
			URLs:           urls,
			Locations:      locations,
		})
	}

	// we have some readers (with no values); let's try to turn into licenses if we can
	for _, content := range b.contents {
		set.Add(b.buildFromContents(ctx, content)...)
	}

	if set.Empty() && len(b.urls) > 0 {
		// if we have no values or contents, but we do have URLs, let's make a license with the URLs
		// try to enrich the license by looking up the URL in the SPDX database
		license := License{
			Type:      b.tp,
			URLs:      b.urls,
			Locations: locations,
		}

		// attempt to fill in missing license information from the first URL
		if len(b.urls) > 0 {
			if info, found := spdxlicense.LicenseByURL(b.urls[0]); found {
				license.Value = info.ID
				license.SPDXExpression = info.ID
			}
		}

		set.Add(license)
	}

	return set
}

func (b *licenseBuilder) buildFromContents(ctx context.Context, contents io.ReadCloser) []License {
	if !licenses.IsContextLicenseScannerSet(ctx) {
		// we do not have a scanner; we don't want to create one; we sha256 the content and populate the value
		internal, err := contentFromReader(contents)
		if err != nil {
			log.WithFields("error", err).Trace("could not read content")
			return nil
		}
		return []License{b.licenseFromContentHash(internal)}
	}

	scanner, err := licenses.ContextLicenseScanner(ctx)
	if err != nil {
		log.WithFields("error", err).Trace("could not find license scanner")
		internal, err := contentFromReader(contents)
		if err != nil {
			log.WithFields("error", err).Trace("could not read content")
			return nil
		}
		return []License{b.licenseFromContentHash(internal)}
	}

	evidence, content, err := scanner.FindEvidence(ctx, contents)
	if err != nil {
		log.WithFields("error", err).Trace("scanner failed to scan contents")
		return nil
	}

	if len(evidence) > 0 {
		// we have some ID and offsets to apply to our content; let's make some detailed licenses
		return b.licensesFromEvidenceAndContent(evidence, content)
	}
	// scanner couldn't find anything, but we still have the file contents; sha256 and send it back with value
	return []License{b.licenseFromContentHash(string(content))}
}

func (b *licenseBuilder) licensesFromEvidenceAndContent(evidence []licenses.Evidence, content []byte) []License {
	ls := make([]License, 0)
	for _, e := range evidence {
		// basic license
		candidate := License{
			Value:     e.ID,
			Locations: file.NewLocationSet(b.locations...),
			Type:      b.tp,
		}
		// get content offset
		if e.Start >= 0 && e.End <= len(content) && e.Start <= e.End {
			candidate.Contents = string(content[e.Start:e.End])
		}
		// check for SPDX Validity
		if ex, err := license.ParseExpression(e.ID); err == nil {
			candidate.SPDXExpression = ex
		}

		ls = append(ls, candidate)
	}
	return ls
}

func (b *licenseBuilder) licenseFromContentHash(content string) License {
	hash := sha256HexFromString(content)
	value := "sha256:" + hash

	return License{
		Value:     value,
		Contents:  content,
		Type:      b.tp,
		Locations: file.NewLocationSet(b.locations...),
	}
}

func contentFromReader(r io.Reader) (string, error) {
	bytes, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytes)), nil
}

func sha256HexFromString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}
