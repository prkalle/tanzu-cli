// Copyright 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package registry

//go:generate counterfeiter -o ../fakes/registy.go --fake-name Registry . Registry

// Registry defines the Registry interface
type Registry interface {
	// ListImageTags lists all tags of the given image.
	ListImageTags(imageName string) ([]string, error)
	// GetFile gets the file content bundled in the given image:tag.
	// If filename is empty, it will get the first file.
	GetFile(imageWithTag string, filename string) ([]byte, error)
	// GetFiles get all the files content bundled in the given image:tag.
	GetFiles(imageWithTag string) (map[string][]byte, error)
	// DownloadBundle downloads OCI bundle similar to `imgpkg pull -b` command
	// It is recommended to use this function when downloading imgpkg bundle
	DownloadBundle(imageName, outputDir string) error
	// DownloadImage downloads an OCI image similarly to the `imgpkg pull -i` command
	DownloadImage(imageName, outputDir string) error
	// GetImageDigest gets the digest of an OCI image similar to the `imgpkg tag resolve -i` command
	GetImageDigest(imageWithTag string) (string, string, error)
	// CopyImageToTar downloads the image as tar file
	// This is equivalent to `imgpkg copy --image <image> --to-tar <tar-file-path>` command
	CopyImageToTar(sourceImageName, destTarFile string) error
	// CopyImageFromTar publishes the image to destination repository from specified tar file
	// This is equivalent to `imgpkg copy --tar <file> --to-repo <dest-repo>` command
	CopyImageFromTar(sourceTarFile, destImageRepo string) error
	// PushImage publishes the image to the specified location
	// This is equivalent to `imgpkg push -i <image> -f <filepath>`
	PushImage(imageWithTag string, filePaths []string) error
	// ResolveImage invokes `imgpkg tag resolve -i <image>` command
	ResolveImage(imageWithTag string) error
}
