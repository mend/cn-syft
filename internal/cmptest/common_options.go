package cmptest

import (
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/syft/internal/evidence"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func DefaultOptions() []cmp.Option {
	return BuildOptions(nil, nil)
}

func DefaultCommonOptions() []cmp.Option {
	return CommonOptions(nil, nil, nil)
}

func DefaultIgnoreLocationLayerOptions() []cmp.Option {
	return BuildOptions(LicenseComparerWithoutLocationLayer, LocationComparerWithoutLayer)
}

func BuildOptions(licenseCmp LicenseComparer, locationCmp LocationComparer) []cmp.Option {
	return CommonOptions(licenseCmp, locationCmp, nil)
}

//nolint:funlen
func CommonOptions(licenseCmp LicenseComparer, locationCmp LocationComparer, copyrightCmp CopyrightComparer) []cmp.Option {
	if licenseCmp == nil {
		licenseCmp = DefaultLicenseComparer
	}

	if locationCmp == nil {
		locationCmp = DefaultLocationComparer
	}

	if copyrightCmp == nil {
		copyrightCmp = DefaultCopyrightComparer
	}

	return []cmp.Option{
		cmpopts.IgnoreFields(pkg.Package{}, "id"),      // note: ID is not deterministic for test purposes
		cmpopts.IgnoreFields(pkg.Package{}, "FoundBy"), // not necessary in most tests
		cmpopts.SortSlices(pkg.Less),
		cmpopts.SortSlices(DefaultRelationshipComparer),
		cmp.Comparer(buildSetComparer[file.Location, file.LocationSet](locationCmp, locationSorter)),
		cmp.Comparer(buildSetComparer[pkg.License, pkg.LicenseSet](licenseCmp)),
		cmp.Comparer(
			func(x, y pkg.CopyrightsSet) bool {
				xs := x.ToSlice()
				ys := y.ToSlice()

				if len(xs) != len(ys) {
					return false
				}
				for i, xe := range xs {
					ye := ys[i]
					if !copyrightCmp(xe, ye) {
						return false
					}
				}
				return true
			},
		),
		cmp.Comparer(locationCmp),
		cmp.Comparer(licenseCmp),
		cmp.Comparer(copyrightCmp),
	}
}

// LocationSorter always sorts by evidence annotations first, then by access path, then by real path.
// This intentionally does not consider layer details since some test fixtures have no layer information
// on the left side of the comparison (expected) and does on the right side (actual).
func locationSorter(a, b file.Location) int {
	// compare by evidence annotations first...
	aEvidence := a.Annotations[evidence.AnnotationKey]
	bEvidence := b.Annotations[evidence.AnnotationKey]

	if aEvidence != bEvidence {
		if aEvidence == evidence.PrimaryAnnotation {
			return -1
		}
		if bEvidence == evidence.PrimaryAnnotation {
			return 1
		}

		if aEvidence > bEvidence {
			return -1
		}
		if bEvidence > aEvidence {
			return 1
		}
	}

	// ...then by paths
	if a.AccessPath != b.AccessPath {
		return strings.Compare(a.AccessPath, b.AccessPath)
	}

	return strings.Compare(a.RealPath, b.RealPath)
}
