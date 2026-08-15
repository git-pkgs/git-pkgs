package database

import "testing"

func TestSchemaMigrationsCoverSupportedVersions(t *testing.T) {
	for version := oldestSchemaVersion; version < SchemaVersion; version++ {
		if _, ok := schemaMigrations[version]; !ok {
			t.Errorf("missing schema migration from version %d", version)
		}
	}
}
