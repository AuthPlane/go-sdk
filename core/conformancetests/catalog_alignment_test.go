package conformancetests

// Catalog alignment verification is performed by the report generator in
// harness_test.go after all tests run. The generateReports function iterates
// over all catalog case IDs and marks any unregistered case as "not_run".
//
// An explicit verification function is provided here and called from TestMain
// (via the afterRunChecks mechanism) to fail the suite if any catalog case ID
// is missing a conformance test.
//
// This file intentionally contains no Test functions — the alignment check
// runs in TestMain after m.Run() to guarantee all Case() calls have fired.

import (
	"fmt"
	"slices"
)

// verifyCatalogAlignment checks that every catalog case ID has a registered
// test, and vice versa. Returns a list of error messages (empty on success).
func verifyCatalogAlignment() []string {
	_, catalogIDs, err := loadCatalogMetadata()
	if err != nil {
		return []string{fmt.Sprintf("load catalog: %v", err)}
	}

	registeredIDs := registry.AllCaseIDs()
	var errs []string

	for _, id := range catalogIDs {
		if !slices.Contains(registeredIDs, id) {
			errs = append(errs, fmt.Sprintf("catalog case %q has no conformance test", id))
		}
	}

	for _, id := range registeredIDs {
		if !slices.Contains(catalogIDs, id) {
			errs = append(errs, fmt.Sprintf("conformance test registers unknown case %q (not in catalog)", id))
		}
	}

	return errs
}
