/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	corev1alpha1 "github.com/kaleido-io/paladin/operator/api/v1alpha1"
	"github.com/kaleido-io/paladin/toolkit/pkg/solutils"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/yaml"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("usage: go run ./contractpkg generate|template [ARGS]"))
		os.Exit(1)
		return
	}
	switch os.Args[1] {
	case "generate":
		if err := generateSmartContracts(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "template":
		if err := template(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, fmt.Errorf("usage: go run ./contractpkg generate|template [ARGS]"))
		os.Exit(1)
	}
	os.Exit(0)
}

type ContractMap map[string]*ContractMapBuild

type ContractMapBuild struct {
	Filename   string            `json:"filename"`
	LinkedLibs map[string]string `json:"linkedContracts"`
	Params     any               `json:"params"`
}

func generateSmartContracts() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: go run ./contractpkg generate [path/to/contractMap.json]")
	}

	var buildMap ContractMap
	mapFileData, err := os.ReadFile(os.Args[2])
	if err == nil {
		err = json.Unmarshal(mapFileData, &buildMap)
	}
	if err != nil {
		return fmt.Errorf("failed to parse build map: %s", err)
	}

	for name, build := range buildMap {
		if err := buildMap.process(name, build); err != nil {
			return err
		}
	}

	// See https://github.com/kubernetes-sigs/kustomize/issues/119 for this bit of stupidity
	var kustomizeMap map[string]any
	kustomizeFileData, err := os.ReadFile("config/samples/kustomization.yaml")
	if err == nil {
		err = yaml.Unmarshal(kustomizeFileData, &kustomizeMap)
	}
	if err != nil {
		return err
	}
	for name := range buildMap {
		expectedEntry := fmt.Sprintf("core_v1alpha1_smartcontractdeployment_%s.yaml", name)
		found := false
		for _, entry := range kustomizeMap["resources"].([]any) {
			if entry.(string) == expectedEntry {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("you need to manually add %s to config/samples/kustomization.yaml", expectedEntry)
		}
	}

	return nil
}

func (m *ContractMap) process(name string, b *ContractMapBuild) error {
	outPath := fmt.Sprintf("config/samples/core_v1alpha1_smartcontractdeployment_%s.yaml", name)

	var build solutils.SolidityBuildWithLinks
	inBuildData, err := os.ReadFile(b.Filename)
	if err == nil {
		err = json.Unmarshal(inBuildData, &build)
	}
	if err != nil {
		return err
	}
	if b.Params == nil {
		b.Params = map[string]any{}
	}
	requiredBuilds := []string{}
	linkedContracts := map[string]string{}

	if build.ABI == nil {
		return fmt.Errorf("no ABI: %s", b.Filename)
	}

	if len(build.Bytecode) == 0 || !strings.HasPrefix(build.Bytecode, "0x") {
		return fmt.Errorf("bad bytecode: %s", b.Filename)
	}

	linkReferencesJSON := ""
	if len(build.LinkReferences) > 0 {
		linkReferencesJSON = tktypes.JSONString(build.LinkReferences).Pretty()
		libCount := 0
		for _, libsInFile := range build.LinkReferences {
			for range libsInFile {
				libCount++
			}
		}

		for libName, link := range b.LinkedLibs {
			link = strings.ReplaceAll(link, "_", "-")
			requiredBuilds = append(requiredBuilds, link)
			l := fmt.Sprintf(`{{index .status.resolvedContractAddresses "%s"}}`, link)
			linkedContracts[libName] = l
		}

		if len(b.LinkedLibs) != libCount {
			return fmt.Errorf("mismatch in links for unlinked Solidity %s expected=%d provided=%d", name, libCount, len(b.LinkedLibs))
		}
	}
	firstNameSegment := strings.SplitN(name, "_", 2)[0]
	scd := corev1alpha1.SmartContractDeployment{
		TypeMeta: v1.TypeMeta{
			APIVersion: "core.paladin.io/v1alpha1",
			Kind:       "SmartContractDeployment",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: strings.ReplaceAll(name, "_", "-"),
			Labels: map[string]string{
				"app.kubernetes.io/name":       "operator-go",
				"app.kubernetes.io/managed-by": "kustomize",
			},
		},
		Spec: corev1alpha1.SmartContractDeploymentSpec{
			Node:                        "node1",
			TxType:                      "public",
			From:                        fmt.Sprintf("%s.operator", firstNameSegment),
			ParamsJSON:                  tktypes.JSONString(b.Params).Pretty(),
			ABIJSON:                     tktypes.JSONString(build.ABI).Pretty(),
			Bytecode:                    build.Bytecode,
			LinkReferencesJSON:          linkReferencesJSON,
			RequiredContractDeployments: requiredBuilds,
			LinkedContracts:             linkedContracts,
		},
	}

	outData, err := yaml.Marshal(scd)
	if err != nil {
		return err
	}

	return os.WriteFile(outPath, outData, 0664)

}

// adjust all .yaml files in the directory to use the new template syntax
func template() error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: go run ./contractpkg template [src] [dist]")
	}
	srcDir := os.Args[2]
	destDir := os.Args[3]

	// Remove the destination directory if it exists
	os.RemoveAll(destDir)

	// Step 1: Create the destination directory if it doesn't exist
	err := os.MkdirAll(destDir, 0755)
	if err != nil {
		return fmt.Errorf("Error creating directory %s: %v", destDir, err)
	}

	// Step 2: Copy files from source patterns to the destination directory
	sourcePatterns := []string{
		"core_v1*",
		"cert*",
	}

	for _, pattern := range sourcePatterns {
		pattern = filepath.Join(srcDir, pattern)
		files, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("Error finding files with pattern %s: %v", pattern, err)
		}

		for _, srcFile := range files {
			dstFile := filepath.Join(destDir, filepath.Base(srcFile))
			err := copyFile(srcFile, dstFile)
			if err != nil {
				return fmt.Errorf("Error copying file from %s to %s: %v", srcFile, dstFile, err)
			}
		}
	}

	// Step 3: Process all .yaml files in the destination directory
	files, err := filepath.Glob(filepath.Join(destDir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("Error finding files: %v", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("No '.yaml' files found in the directory")
	}

	// Compile the regular expression pattern
	pattern := regexp.MustCompile(`\{\{([^}]*)\}\}`)

	// Iterate over each file
	for _, file := range files {
		// Read the file content
		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("Error reading file %s: %v", file, err)
		}

		// Perform the regex replacement
		newContent := pattern.ReplaceAllString(string(content), "{{ `{{${1}}}` }}")

		// Add conditional wrapper around the content
		conditions := []string{"(eq .Values.mode \"devnet\")"}

		if strings.Contains(file, "smartcontractdeployment") {
			// Include additional condition if file contains "smartcontractdeployment"
			conditions = append(conditions, "(eq .Values.mode \"smartcontractdeployment\")")
		}

		// Build the condition string for the template
		var condition string
		if len(conditions) == 1 {
			// Single condition doesn't need 'or'
			condition = conditions[0]
		} else {
			// Multiple conditions use 'or' to combine them
			condition = fmt.Sprintf("(or %s)", strings.Join(conditions, " "))
		}

		// Wrap newContent with the conditional template
		newContent = fmt.Sprintf("{{- if %s }}\n\n%s\n{{- end }}", condition, newContent)

		// Write the modified content back to the same file
		err = os.WriteFile(file, []byte(newContent), fs.FileMode(0644))
		if err != nil {
			return fmt.Errorf("Error writing file %s: %v", file, err)
		}

		// Print a message indicating the file has been processed
		fmt.Printf("Processed %s\n", file)
	}
	return nil
}

// Helper function to copy a file from src to dst
func copyFile(src, dst string) error {
	// Open the source file
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("Error opening source file %s: %w", src, err)
	}
	defer srcFile.Close()

	// Create the destination file
	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("Error creating destination file %s: %w", dst, err)
	}
	defer dstFile.Close()

	// Copy the content from source to destination
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("Error copying from %s to %s: %w", src, dst, err)
	}

	// Flush and close the files
	err = dstFile.Sync()
	if err != nil {
		return fmt.Errorf("Error syncing destination file %s: %w", dst, err)
	}

	return nil
}
