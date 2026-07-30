package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
)

// TestFixture represents a deterministic test data structure
type TestFixture struct {
	Name           string
	Description    string
	Setup          func(baseDir string) error
	ExpectedFiles  int
	ExpectedDirs   int
	ExpectedChunks int
}

// GetAllFixtures returns all available test fixtures
func GetAllFixtures() []TestFixture {
	return []TestFixture{
		SingleSmallFile(),
		SingleLargeFile(),
		FlatDirectory(),
		NestedDirectory(),
		DeepHierarchy(),
		MixedSizes(),
	}
}

// SingleSmallFile creates a single file well below the chunk size (4KB default)
// Use case: Testing basic file DAG creation, single leaf DAGs
func SingleSmallFile() TestFixture {
	return TestFixture{
		Name:        "single_small_file",
		Description: "Single 1KB file - no chunking",
		Setup: func(baseDir string) error {
			filePath := filepath.Join(baseDir, "small.txt")
			content := make([]byte, 1024) // 1KB
			for i := range content {
				content[i] = byte('A' + (i % 26))
			}
			return os.WriteFile(filePath, content, 0644)
		},
		ExpectedFiles:  1,
		ExpectedDirs:   0,
		ExpectedChunks: 0,
	}
}

// SingleLargeFile creates a single file above the chunk size requiring chunking
// Use case: Testing file chunking, merkle tree construction for chunks
func SingleLargeFile() TestFixture {
	return TestFixture{
		Name:        "single_large_file",
		Description: "Single 10KB file - requires chunking (default chunk size 4KB)",
		Setup: func(baseDir string) error {
			filePath := filepath.Join(baseDir, "large.txt")
			content := make([]byte, 10*1024) // 10KB
			for i := range content {
				content[i] = byte('A' + (i % 26))
			}
			return os.WriteFile(filePath, content, 0644)
		},
		ExpectedFiles:  1,
		ExpectedDirs:   0,
		ExpectedChunks: 3, // 10KB / 4KB = 3 chunks
	}
}

// FlatDirectory creates a directory with multiple files at the same level
// Use case: Testing parent-child relationships, merkle proofs for siblings
func FlatDirectory() TestFixture {
	return TestFixture{
		Name:        "flat_directory",
		Description: "One directory with 5 small files (no subdirectories)",
		Setup: func(baseDir string) error {
			files := []struct {
				name string
				size int
			}{
				{"file1.txt", 512},
				{"file2.txt", 1024},
				{"file3.txt", 768},
				{"file4.txt", 2048},
				{"file5.txt", 256},
			}

			for _, f := range files {
				filePath := filepath.Join(baseDir, f.name)
				content := make([]byte, f.size)
				for i := range content {
					content[i] = byte('A' + (i % 26))
				}
				if err := os.WriteFile(filePath, content, 0644); err != nil {
					return err
				}
			}
			return nil
		},
		ExpectedFiles:  5,
		ExpectedDirs:   0,
		ExpectedChunks: 0,
	}
}

// NestedDirectory creates a two-level directory structure
// Use case: Testing directory traversal, multiple parent-child levels
func NestedDirectory() TestFixture {
	return TestFixture{
		Name:        "nested_directory",
		Description: "Two-level hierarchy: root -> 2 subdirs -> 2 files each",
		Setup: func(baseDir string) error {
			structure := map[string][]string{
				"subdir1": {"file1a.txt", "file1b.txt"},
				"subdir2": {"file2a.txt", "file2b.txt"},
			}

			for dir, files := range structure {
				dirPath := filepath.Join(baseDir, dir)
				if err := os.MkdirAll(dirPath, 0755); err != nil {
					return err
				}

				for i, fileName := range files {
					filePath := filepath.Join(dirPath, fileName)
					content := make([]byte, 1024+i*512) // Vary sizes
					for j := range content {
						content[j] = byte('A' + (j % 26))
					}
					if err := os.WriteFile(filePath, content, 0644); err != nil {
						return err
					}
				}
			}
			return nil
		},
		ExpectedFiles:  4,
		ExpectedDirs:   2,
		ExpectedChunks: 0,
	}
}

// DeepHierarchy creates a deeply nested directory structure
// Use case: Testing deep path traversal, verification paths through multiple levels
func DeepHierarchy() TestFixture {
	return TestFixture{
		Name:        "deep_hierarchy",
		Description: "Five-level deep directory structure",
		Setup: func(baseDir string) error {
			// Create a 5-level deep structure: level1/level2/level3/level4/level5/file.txt
			deepPath := filepath.Join(baseDir, "level1", "level2", "level3", "level4", "level5")
			if err := os.MkdirAll(deepPath, 0755); err != nil {
				return err
			}

			// Add a file at each level
			for i := 1; i <= 5; i++ {
				levelPath := filepath.Join(baseDir, "level1")
				for j := 2; j <= i; j++ {
					levelPath = filepath.Join(levelPath, fmt.Sprintf("level%d", j))
				}

				filePath := filepath.Join(levelPath, fmt.Sprintf("file_at_level_%d.txt", i))
				content := make([]byte, i*256) // Increasing sizes
				for k := range content {
					content[k] = byte('A' + (k % 26))
				}
				if err := os.WriteFile(filePath, content, 0644); err != nil {
					return err
				}
			}

			return nil
		},
		ExpectedFiles:  5,
		ExpectedDirs:   5,
		ExpectedChunks: 0,
	}
}

// MixedSizes creates a structure with both small and large files requiring chunking
// Use case: Testing mixed scenarios with and without chunking
func MixedSizes() TestFixture {
	return TestFixture{
		Name:        "mixed_sizes",
		Description: "Directory with both small files and large files requiring chunking",
		Setup: func(baseDir string) error {
			files := []struct {
				name string
				size int
			}{
				{"tiny.txt", 128},             // Very small
				{"small.txt", 2048},           // Below chunk size
				{"medium.txt", 5 * 1024},      // Requires 2 chunks
				{"large.txt", 15 * 1024},      // Requires 4 chunks
				{"exact_chunk.txt", 4 * 1024}, // Exactly one chunk
			}

			for _, f := range files {
				filePath := filepath.Join(baseDir, f.name)
				content := make([]byte, f.size)
				for i := range content {
					content[i] = byte('A' + (i % 26))
				}
				if err := os.WriteFile(filePath, content, 0644); err != nil {
					return err
				}
			}
			return nil
		},
		ExpectedFiles:  5,
		ExpectedDirs:   0,
		// 6 chunk positions (0 + 0 + 2 + 4 + 0 - exact_chunk.txt is exactly one
		// chunk size, so it is never chunked), but chunk bytes are a function of
		// absolute offset, so medium.txt[0] and large.txt[0] are the same 4096
		// bytes under the same "0" name and dedupe into one shared leaf.
		ExpectedChunks: 5,
	}
}

// CreateFixture creates a test fixture in the specified directory
// Returns the path to the created fixture directory
func CreateFixture(baseDir string, fixture TestFixture) (string, error) {
	fixturePath := filepath.Join(baseDir, fixture.Name)
	if err := os.MkdirAll(fixturePath, 0755); err != nil {
		return "", fmt.Errorf("failed to create fixture directory: %w", err)
	}

	if err := fixture.Setup(fixturePath); err != nil {
		os.RemoveAll(fixturePath)
		return "", fmt.Errorf("failed to setup fixture %s: %w", fixture.Name, err)
	}

	return fixturePath, nil
}

// CreateAllFixtures creates all test fixtures in the base directory
// Returns a map of fixture name to fixture path
func CreateAllFixtures(baseDir string) (map[string]string, error) {
	fixtures := GetAllFixtures()
	fixturePaths := make(map[string]string)

	for _, fixture := range fixtures {
		path, err := CreateFixture(baseDir, fixture)
		if err != nil {
			// Clean up any created fixtures on error
			for _, p := range fixturePaths {
				os.RemoveAll(p)
			}
			return nil, err
		}
		fixturePaths[fixture.Name] = path
	}

	return fixturePaths, nil
}

// GetFixtureByName returns a specific fixture by name
func GetFixtureByName(name string) (TestFixture, bool) {
	for _, f := range GetAllFixtures() {
		if f.Name == name {
			return f, true
		}
	}
	return TestFixture{}, false
}

// TestAllFixtures verifies that all fixtures can be created successfully
func TestAllFixtures(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fixtures_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fixtures := GetAllFixtures()

	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			fixturePath, err := CreateFixture(tmpDir, fixture)
			if err != nil {
				t.Fatalf("Failed to create fixture: %v", err)
			}

			// Verify the fixture was created
			if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
				t.Errorf("Fixture directory was not created: %s", fixturePath)
			}

			// Create a DAG from the fixture
			d, err := dag.CreateDag(fixturePath, true)
			if err != nil {
				t.Fatalf("Failed to create DAG from fixture: %v", err)
			}

			// Verify the DAG
			if err := d.Verify(); err != nil {
				t.Errorf("DAG verification failed for fixture %s: %v", fixture.Name, err)
			}

			// Count the actual files and directories
			var actualFiles, actualDirs int
			for _, leaf := range d.Leafs {
				switch leaf.Type {
				case dag.FileLeafType:
					actualFiles++
				case dag.DirectoryLeafType:
					actualDirs++
				}
			}

			// Note: We include the root directory in the count
			expectedDirs := fixture.ExpectedDirs + 1 // +1 for root

			if actualFiles != fixture.ExpectedFiles {
				t.Errorf("Expected %d files, got %d", fixture.ExpectedFiles, actualFiles)
			}

			if actualDirs != expectedDirs {
				t.Logf("Note: Expected %d dirs (including root), got %d", expectedDirs, actualDirs)
			}

			t.Logf("Fixture '%s': %d files, %d dirs, %d total leaves",
				fixture.Name, actualFiles, actualDirs, len(d.Leafs))
		})
	}
}

// RunTestWithFixture is a helper to run a test function against a specific fixture
func RunTestWithFixture(t *testing.T, fixtureName string, testFunc func(*testing.T, *dag.Dag, string)) {
	tmpDir, err := os.MkdirTemp("", "fixture_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fixture, ok := GetFixtureByName(fixtureName)
	if !ok {
		t.Fatalf("Fixture not found: %s", fixtureName)
	}

	fixturePath, err := CreateFixture(tmpDir, fixture)
	if err != nil {
		t.Fatalf("Failed to create fixture: %v", err)
	}

	dag, err := dag.CreateDag(fixturePath, true)
	if err != nil {
		t.Fatalf("Failed to create DAG from fixture: %v", err)
	}

	testFunc(t, dag, fixturePath)
}

// RunTestWithAllFixtures runs a test function against all fixtures
func RunTestWithAllFixtures(t *testing.T, testFunc func(*testing.T, *dag.Dag, TestFixture, string)) {
	// Set default chunk size to ensure consistency across tests
	dag.SetChunkSize(4096)

	tmpDir, err := os.MkdirTemp("", "fixtures_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fixtures := GetAllFixtures()

	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			fixturePath, err := CreateFixture(tmpDir, fixture)
			if err != nil {
				t.Fatalf("Failed to create fixture: %v", err)
			}

			dag, err := dag.CreateDag(fixturePath, false)
			if err != nil {
				t.Fatalf("Failed to create DAG from fixture: %v", err)
			}

			testFunc(t, dag, fixture, fixturePath)
		})
	}
}

// GetMultiFileFixtures returns fixtures that have multiple files (useful for partial DAG tests)
func GetMultiFileFixtures() []TestFixture {
	return []TestFixture{
		FlatDirectory(),
		NestedDirectory(),
		DeepHierarchy(),
		MixedSizes(),
	}
}

// GetSingleFileFixtures returns fixtures with only one file
func GetSingleFileFixtures() []TestFixture {
	return []TestFixture{
		SingleSmallFile(),
		SingleLargeFile(),
	}
}

// GetChunkingFixtures returns fixtures that test chunking behavior
func GetChunkingFixtures() []TestFixture {
	return []TestFixture{
		SingleLargeFile(),
		MixedSizes(),
	}
}

// GetHierarchyFixtures returns fixtures with nested directory structures
func GetHierarchyFixtures() []TestFixture {
	return []TestFixture{
		NestedDirectory(),
		DeepHierarchy(),
	}
}

// RunTestWithMultiFileFixtures runs a test against all fixtures that have multiple files
func RunTestWithMultiFileFixtures(t *testing.T, testFunc func(*testing.T, *dag.Dag, TestFixture, string)) {
	// Set default chunk size to ensure consistency across tests
	dag.SetChunkSize(4096)

	tmpDir, err := os.MkdirTemp("", "fixtures_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fixtures := GetMultiFileFixtures()

	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			fixturePath, err := CreateFixture(tmpDir, fixture)
			if err != nil {
				t.Fatalf("Failed to create fixture: %v", err)
			}

			dag, err := dag.CreateDag(fixturePath, false)
			if err != nil {
				t.Fatalf("Failed to create DAG from fixture: %v", err)
			}

			testFunc(t, dag, fixture, fixturePath)
		})
	}
}

// RunTestWithChunkingFixtures runs a test against fixtures that test chunking
func RunTestWithChunkingFixtures(t *testing.T, testFunc func(*testing.T, *dag.Dag, TestFixture, string)) {
	tmpDir, err := os.MkdirTemp("", "fixtures_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fixtures := GetChunkingFixtures()

	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			fixturePath, err := CreateFixture(tmpDir, fixture)
			if err != nil {
				t.Fatalf("Failed to create fixture: %v", err)
			}

			dag, err := dag.CreateDag(fixturePath, true)
			if err != nil {
				t.Fatalf("Failed to create DAG from fixture: %v", err)
			}

			testFunc(t, dag, fixture, fixturePath)
		})
	}
}
