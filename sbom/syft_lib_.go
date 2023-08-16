//
// https://gist.github.com/wagoodman/57ed59a6d57600c23913071b8470175b
//
//

package main

import (
	"fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// use syft to discover packages + distro only
func main() {
	userInput := "ubuntu:latest"

	src, cleanup, err := source.New(userInput, nil, nil)
	if err != nil {
		panic(fmt.Errorf("failed to construct source from user input %q: %w", userInput, err))
	}
	if cleanup != nil {
		defer cleanup()
	}

	result := sbom.SBOM{
		Source: src.Metadata,
		// TODO: we should have helper functions for getting this built from exported library functions
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v-your-syft-version-here", // shows up in the output for many different formats
		},
	}

	packageCatalog, relationships, theDistro, err := syft.CatalogPackages(src, source.SquashedScope)
	if err != nil {
		panic(err)
	}

	result.Artifacts.PackageCatalog = packageCatalog
	result.Artifacts.Distro = theDistro
	result.Relationships = relationships

	// you can use other formats such as format.CycloneDxJSONOption or format.SPDXJSONOption ...
	bytes, err := syft.Encode(result, format.JSONOption)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bytes))
}
more-catalogers.go
package main

import (
	"crypto"
	"fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// use more catalogers than just the pacakge catalogers
func main() {
	userInput := "ubuntu:latest"

	src, cleanup, err := source.New(userInput, nil, nil)
	if err != nil {
		panic(fmt.Errorf("failed to construct source from user input %q: %w", userInput, err))
	}
	if cleanup != nil {
		defer cleanup()
	}

	result := sbom.SBOM{
		Source: src.Metadata,
		// TODO: we should have helper functions for getting this built from exported library functions
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v-your-syft-version-here", // shows up in the output for many different formats
		},
	}

	enabledTasks, err := tasks(source.SquashedScope)
	if err != nil {
		panic(fmt.Errorf("unable to configure tasks"))
	}

	for _, currentTask := range enabledTasks {

		taskRelationships, err := currentTask(&result.Artifacts, src)
		if err != nil {
			panic(err)
		}

		result.Relationships = append(result.Relationships, taskRelationships...)
	}

	// you can use other formats such as format.CycloneDxJSONOption or format.SPDXJSONOption ...
	bytes, err := syft.Encode(result, format.JSONOption)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bytes))
}

type task func(*sbom.Artifacts, *source.Source) ([]artifact.Relationship, error)

func tasks(scope source.Scope) ([]task, error) {
	var allTasks []task

	generators := []func(source.Scope) (task, error){
		generateCatalogPackagesTask,
		generateCatalogFileMetadataTask,
		generateCatalogFileDigestsTask,
	}

	for _, generator := range generators {
		currentTask, err := generator(scope)
		if err != nil {
			return nil, err
		}

		if currentTask != nil {
			allTasks = append(allTasks, currentTask)
		}
	}

	return allTasks, nil
}

func generateCatalogPackagesTask(scope source.Scope) (task, error) {
	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		packageCatalog, relationships, theDistro, err := syft.CatalogPackages(src, scope)
		if err != nil {
			return nil, err
		}

		results.PackageCatalog = packageCatalog
		results.Distro = theDistro

		return relationships, nil
	}

	return task, nil
}

func generateCatalogFileMetadataTask(scope source.Scope) (task, error) {
	metadataCataloger := file.NewMetadataCataloger()

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(scope)
		if err != nil {
			return nil, err
		}

		result, err := metadataCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileMetadata = result
		return nil, nil
	}

	return task, nil
}

func generateCatalogFileDigestsTask(scope source.Scope) (task, error) {
	supportedHashAlgorithms := make(map[string]crypto.Hash)
	for _, h := range []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA256,
	} {
		supportedHashAlgorithms[file.DigestAlgorithmName(h)] = h
	}

	var hashes []crypto.Hash
	// add others digests if you'd like!
	for _, hashStr := range []string{"sha256"} {
		name := file.CleanDigestAlgorithmName(hashStr)
		hashObj, ok := supportedHashAlgorithms[name]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		hashes = append(hashes, hashObj)
	}

	digestsCataloger, err := file.NewDigestsCataloger(hashes)
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(scope)
		if err != nil {
			return nil, err
		}

		result, err := digestsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileDigests = result
		return nil, nil
	}

	return task, nil
}
