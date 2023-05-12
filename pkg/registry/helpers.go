// Copyright 2022-23 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/base64"
	"fmt"
	urlpkg "net/url"
	"os"
	"runtime"
	"strconv"

	regname "github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"golang.org/x/net/http/httpproxy"

	"github.com/vmware-tanzu/tanzu-cli/pkg/configpaths"
	"github.com/vmware-tanzu/tanzu-cli/pkg/constants"
	configlib "github.com/vmware-tanzu/tanzu-plugin-runtime/config"
	configtypes "github.com/vmware-tanzu/tanzu-plugin-runtime/config/types"
)

type CertOptions struct {
	CACertPaths    []string
	SkipCertVerify bool
	Insecure       bool
}

func GetRegistryCertOptions(registryHost string) (*CertOptions, error) {
	registryCertOpts := &CertOptions{
		SkipCertVerify: false,
		Insecure:       false,
	}

	if runtime.GOOS == "windows" {
		err := AddRegistryTrustedRootCertsFileForWindows(registryCertOpts)
		if err != nil {
			return nil, err
		}
	}

	// check if the custom cert data is configured for the registry
	if exists, _ := configlib.CertExists(registryHost); !exists {
		err := checkForProxyConfigAndUpdateCert(registryHost, "https", registryCertOpts)
		if err != nil {
			return nil, errors.Wrap(err, "failed to check for proxy config and update the cert")
		}
		return registryCertOpts, nil
	}
	cert, err := configlib.GetCert(registryHost)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get the custom certificate configuration for host %q", registryHost)
	}

	err = updateRegistryCertOptions(cert, registryCertOpts)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to updated the registry cert options")
	}

	scheme := "https"
	if registryCertOpts.Insecure {
		scheme = "http"
	}

	err = checkForProxyConfigAndUpdateCert(registryHost, scheme, registryCertOpts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to check for proxy config and update the cert")
	}
	return registryCertOpts, nil
}

// updateRegistryCertOptions sets the registry options by taking the custom certificate data configured for registry as input
func updateRegistryCertOptions(cert *configtypes.Cert, registryCertOpts *CertOptions) error {
	if cert.SkipCertVerify != "" {
		skipVerifyCerts, _ := strconv.ParseBool(cert.SkipCertVerify)
		registryCertOpts.SkipCertVerify = skipVerifyCerts
	}
	if cert.Insecure != "" {
		insecure, _ := strconv.ParseBool(cert.Insecure)
		registryCertOpts.Insecure = insecure
	}

	err := updateCACertData(cert.CACertData, registryCertOpts)
	if err != nil {
		return err
	}

	return nil
}

// AddRegistryTrustedRootCertsFileForWindows adds CA certificate to registry options for Windows environments
func AddRegistryTrustedRootCertsFileForWindows(registryCertOpts *CertOptions) error {
	filePath, err := configpaths.GetRegistryTrustedCACertFileForWindows()
	if err != nil {
		return err
	}
	err = os.WriteFile(filePath, projectsRegistryCA, constants.ConfigFilePermissions)
	if err != nil {
		return errors.Wrapf(err, "failed to write the registry trusted CA cert to file '%s'", filePath)
	}
	registryCertOpts.CACertPaths = append(registryCertOpts.CACertPaths, filePath)
	return nil
}

// GetRegistryName extracts the registry name from the image name with/without image tag
// (e.g. localhost:9876/tanzu-cli/plugins/central:small => localhost:9876)
func GetRegistryName(imageName string) (string, error) {
	tag, err := regname.NewTag(imageName)
	if err != nil {
		return "", errors.Wrapf(err, "unable to fetch registry name from image %q", imageName)
	}
	return tag.Registry.Name(), nil
}

// checkForProxyConfigAndUpdateCert checks if proxy should be used to interact with registry host, if so, checks if user has configured CA cert data
// for proxy host in the configuration file (using "tanzu cert config add --hostname <proxy-host> --ca-certificate /path/to/cacert) and use it
func checkForProxyConfigAndUpdateCert(registryHost, scheme string, registryCertOpts *CertOptions) error {
	proxyURL, err := getProxyURL(registryHost, scheme)
	if err != nil {
		return errors.Wrap(err, "checking proxy configuration")
	}
	// If there is no proxy, nothing to update
	if proxyURL == nil {
		return nil
	}

	// check if user provided cert configuration for proxy host, if so, use only the CACertData
	if exists, _ := configlib.CertExists(proxyURL.Host); !exists {
		return nil
	}
	// get cert provided for the proxy
	cert, err := configlib.GetCert(proxyURL.Host)
	if err != nil {
		return errors.Wrapf(err, "failed to get the custom certificate configuration for host %q", registryHost)
	}

	// If proxy CA cert data is available, overwrite the registry cert data
	err = updateCACertData(cert.CACertData, registryCertOpts)
	if err != nil {
		return err
	}

	return nil
}

func getProxyURL(registryHost, scheme string) (*urlpkg.URL, error) {
	url := fmt.Sprintf("%s://%s", scheme, registryHost)
	parsedURL, err := urlpkg.Parse(url)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse the registry url: %q", url)
	}
	proxyURL, err := httpproxy.FromEnvironment().ProxyFunc()(parsedURL)
	if err != nil {
		return nil, errors.New("failed to get proxy from environment")
	}
	return proxyURL, nil
}

func updateCACertData(caCertData string, registryCertOpts *CertOptions) error {
	if caCertData != "" {
		caCertBytes, err := base64.StdEncoding.DecodeString(caCertData)
		if err != nil {
			return errors.Wrap(err, "unable to decode the base64-encoded custom registry CA certificate string")
		}
		if len(caCertBytes) != 0 {
			filePath, err := configpaths.GetRegistryCertFile()
			if err != nil {
				return err
			}
			err = os.WriteFile(filePath, caCertBytes, 0o644)
			if err != nil {
				return errors.Wrapf(err, "failed to write the custom image registry CA cert to file '%s'", filePath)
			}
			registryCertOpts.CACertPaths = append(registryCertOpts.CACertPaths, filePath)
		}
	}
	return nil
}
