// Copyright 2023 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package registry

import (
	"encoding/base64"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/vmware-tanzu/tanzu-cli/pkg/configpaths"
	configlib "github.com/vmware-tanzu/tanzu-plugin-runtime/config"
	configtypes "github.com/vmware-tanzu/tanzu-plugin-runtime/config/types"
)

func TestRegistrySuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "pkg/registry suite")
}

var _ = Describe("GetRegistryCertOptions", func() {

	Describe("GetRegistryCertOptions without proxy configuration", func() {
		var (
			tanzuConfigFile   *os.File
			tanzuConfigFileNG *os.File
			caCertDataOpt     string
			skipCertVerifyOpt string
			insecureOpt       string
			err               error
		)
		const (
			fakeCACertData = "fake ca cert data"
			testHost       = "test.vmware.com"
			trueStr        = "true"
		)

		BeforeEach(func() {
			tanzuConfigFile, err = os.CreateTemp("", "config")
			Expect(err).To(BeNil())
			os.Setenv("TANZU_CONFIG", tanzuConfigFile.Name())

			tanzuConfigFileNG, err = os.CreateTemp("", "config_ng")
			Expect(err).To(BeNil())
			os.Setenv("TANZU_CONFIG_NEXT_GEN", tanzuConfigFileNG.Name())

		})
		AfterEach(func() {
			os.Unsetenv("TANZU_CONFIG")
			os.Unsetenv("TANZU_CONFIG_NEXT_GEN")
			os.RemoveAll(tanzuConfigFile.Name())
			os.RemoveAll(tanzuConfigFileNG.Name())
		})
		JustBeforeEach(func() {
			caCertDataOptB64 := ""
			if len(caCertDataOpt) > 0 {
				caCertDataOptB64 = base64.StdEncoding.EncodeToString([]byte(caCertDataOpt))
			}
			cert := &configtypes.Cert{
				Host:           testHost,
				CACertData:     caCertDataOptB64,
				SkipCertVerify: skipCertVerifyOpt,
				Insecure:       insecureOpt,
			}
			err := configlib.SetCert(cert)
			Expect(err).To(BeNil())
		})

		Context("When only custom CA cert data is provided for the registry host in the config", func() {
			BeforeEach(func() {
				caCertDataOpt = fakeCACertData
			})
			It("should return success and cert options should have registry cert path updated", func() {
				certOptions, err := GetRegistryCertOptions(testHost)
				Expect(err).To(BeNil())
				Expect(certOptions).ToNot(BeNil())

				regFilePath, err := configpaths.GetRegistryCertFile()
				Expect(err).To(BeNil())
				Expect(certOptions.CACertPaths).To(ContainElement(regFilePath))
				Expect(certOptions.SkipCertVerify).To(Equal(false))
				Expect(certOptions.Insecure).To(Equal(false))
			})
		})

		Context("When the custom CA cert data, skipCertVerify and Insecure options are provided for the registry host in the config", func() {
			BeforeEach(func() {
				caCertDataOpt = fakeCACertData
				skipCertVerifyOpt = trueStr
				insecureOpt = trueStr
			})
			It("should return success and cert options should have registry cert path updated and skipCertVerify and Insecure options are updated", func() {
				certOptions, err := GetRegistryCertOptions(testHost)
				Expect(err).To(BeNil())
				Expect(certOptions).ToNot(BeNil())

				regFilePath, err := configpaths.GetRegistryCertFile()
				Expect(err).To(BeNil())
				Expect(certOptions.CACertPaths).To(ContainElement(regFilePath))
				Expect(certOptions.SkipCertVerify).To(Equal(true))
				Expect(certOptions.Insecure).To(Equal(true))
			})
			It("should return defaults if the registry name doesn't match with the host existing in the config", func() {
				certOptions, err := GetRegistryCertOptions("NonExistingRegistryName")
				Expect(err).To(BeNil())
				Expect(certOptions).ToNot(BeNil())
				// check the cert options returned are default values
				Expect(certOptions.CACertPaths).To(BeEmpty())
				Expect(certOptions.SkipCertVerify).To(Equal(false))
				Expect(certOptions.Insecure).To(Equal(false))

			})
		})

	})

	Describe("GetRegistryCertOptions with proxy configured", func() {
		var (
			tanzuConfigFile   *os.File
			tanzuConfigFileNG *os.File
			caCertDataOpt     string
			skipCertVerifyOpt string
			insecureOpt       string
			noProxyOpt        string
			err               error
		)
		const (
			fakeCACertData      = "fake ca cert data"
			fakeProxyCACertData = "fake proxy ca cert data"
			testHost            = "test.vmware.com"
			trueStr             = "true"
			falseStr            = "false"
			testHTTPProxyHost   = "192.168.116.1:3128"
			testHTTPSProxyHost  = "192.168.116.1:3129"
			testnoProxy         = ".vmware.com"
		)

		BeforeEach(func() {
			tanzuConfigFile, err = os.CreateTemp("", "config")
			Expect(err).To(BeNil())
			os.Setenv("TANZU_CONFIG", tanzuConfigFile.Name())

			tanzuConfigFileNG, err = os.CreateTemp("", "config_ng")
			Expect(err).To(BeNil())
			os.Setenv("TANZU_CONFIG_NEXT_GEN", tanzuConfigFileNG.Name())

			os.Setenv("http_proxy", "http://"+testHTTPProxyHost)
			os.Setenv("https_proxy", "http://"+testHTTPSProxyHost)
		})
		AfterEach(func() {
			os.Unsetenv("TANZU_CONFIG")
			os.Unsetenv("TANZU_CONFIG_NEXT_GEN")
			os.RemoveAll(tanzuConfigFile.Name())
			os.RemoveAll(tanzuConfigFileNG.Name())
			os.Unsetenv("http_proxy")
			os.Unsetenv("https_proxy")
			os.Unsetenv("no_proxy")
		})
		JustBeforeEach(func() {
			caCertDataOptB64 := ""
			if len(caCertDataOpt) > 0 {
				caCertDataOptB64 = base64.StdEncoding.EncodeToString([]byte(caCertDataOpt))
			}
			cert := &configtypes.Cert{
				Host:           testHost,
				CACertData:     caCertDataOptB64,
				SkipCertVerify: skipCertVerifyOpt,
				Insecure:       insecureOpt,
			}
			err := configlib.SetCert(cert)
			Expect(err).To(BeNil())
			os.Setenv("no_proxy", noProxyOpt)
		})

		Context("When custom CA cert data is provided for the registry host in the config and proxy cert config is not provided for the proxy host ", func() {
			BeforeEach(func() {
				caCertDataOpt = fakeCACertData
				//noProxy = ""
			})
			It("should return success and cert options should have registry cert path updated with registry host CA cert data", func() {
				certOptions, err := GetRegistryCertOptions(testHost)
				Expect(err).To(BeNil())
				Expect(certOptions).ToNot(BeNil())

				regFilePath, err := configpaths.GetRegistryCertFile()
				Expect(err).To(BeNil())
				Expect(certOptions.CACertPaths).To(ContainElement(regFilePath))
				certData, err := os.ReadFile(regFilePath)
				Expect(err).To(BeNil())
				Expect(string(certData)).To(Equal(fakeCACertData))
				Expect(certOptions.SkipCertVerify).To(Equal(false))
				Expect(certOptions.Insecure).To(Equal(false))
			})
		})
		Context("When custom CA cert data is provided for the registry host in the config and also proxy cert config provided for the proxy host ", func() {
			BeforeEach(func() {
				caCertDataOpt = fakeCACertData
			})
			It("should return success and cert options should have registry cert path updated with proxy CA cert data", func() {
				cert := &configtypes.Cert{
					Host:       testHTTPSProxyHost,
					CACertData: base64.StdEncoding.EncodeToString([]byte(fakeProxyCACertData)),
				}
				err := configlib.SetCert(cert)
				Expect(err).To(BeNil())

				certOptions, err := GetRegistryCertOptions(testHost)
				Expect(err).To(BeNil())
				Expect(certOptions).ToNot(BeNil())

				regFilePath, err := configpaths.GetRegistryCertFile()
				Expect(err).To(BeNil())
				Expect(certOptions.CACertPaths).To(ContainElement(regFilePath))
				certData, err := os.ReadFile(regFilePath)
				Expect(err).To(BeNil())
				Expect(string(certData)).To(Equal(fakeProxyCACertData))
				Expect(certOptions.SkipCertVerify).To(Equal(false))
				Expect(certOptions.Insecure).To(Equal(false))
			})
		})
		Context("When cert config is NOT provided for the registry host, but proxy cert config provided for the proxy host ", func() {
			BeforeEach(func() {
				caCertDataOpt = fakeCACertData
			})
			It("should return success and cert options should have registry cert path updated with proxy CA cert data", func() {
				// delete the registry host cert config(as it is added for all the test cases)
				err := configlib.DeleteCert(testHost)
				Expect(err).To(BeNil())

				// add proxy cert config
				cert := &configtypes.Cert{
					Host:       testHTTPSProxyHost,
					CACertData: base64.StdEncoding.EncodeToString([]byte(fakeProxyCACertData)),
				}
				err = configlib.SetCert(cert)
				Expect(err).To(BeNil())

				certOptions, err := GetRegistryCertOptions(testHost)
				Expect(err).To(BeNil())
				Expect(certOptions).ToNot(BeNil())

				regFilePath, err := configpaths.GetRegistryCertFile()
				Expect(err).To(BeNil())
				Expect(certOptions.CACertPaths).To(ContainElement(regFilePath))
				certData, err := os.ReadFile(regFilePath)
				Expect(err).To(BeNil())
				Expect(string(certData)).To(Equal(fakeProxyCACertData))
				Expect(certOptions.SkipCertVerify).To(Equal(false))
				Expect(certOptions.Insecure).To(Equal(false))
			})
		})

		Context("When cert config data is provided for the registry host with 'Insecure' option set to true and also proxy cert config provided for the https proxy host ", func() {
			BeforeEach(func() {
				insecureOpt = trueStr
			})
			It("should return success and cert options should have NOT have registry cert path updated with proxy CA cert data since the proxy url should be mapped to http proxy not https proxy", func() {
				cert := &configtypes.Cert{
					Host:       testHTTPSProxyHost,
					CACertData: base64.StdEncoding.EncodeToString([]byte(fakeProxyCACertData)),
				}
				err := configlib.SetCert(cert)
				Expect(err).To(BeNil())

				certOptions, err := GetRegistryCertOptions(testHost)
				Expect(err).To(BeNil())
				Expect(certOptions).ToNot(BeNil())

				regFilePath, err := configpaths.GetRegistryCertFile()
				Expect(err).To(BeNil())
				Expect(certOptions.CACertPaths).To(ContainElement(regFilePath))
				certData, err := os.ReadFile(regFilePath)
				Expect(err).To(BeNil())
				Expect(string(certData)).To(Equal(fakeCACertData))
				Expect(certOptions.SkipCertVerify).To(Equal(false))
				Expect(certOptions.Insecure).To(Equal(true))
			})
		})
		Context("When cert config data is provided for the registry host and also proxy cert config provided for the https proxy host. But the registry host is part of no_proxy list ", func() {
			BeforeEach(func() {
				caCertDataOpt = fakeCACertData
				noProxyOpt = testnoProxy
				skipCertVerifyOpt = trueStr
				insecureOpt = falseStr
			})
			It("should return success and cert options should have NOT have registry cert path updated with proxy CA cert data since the proxy should be skipped as registry host is part of no_proxy list", func() {
				cert := &configtypes.Cert{
					Host:       testHTTPSProxyHost,
					CACertData: base64.StdEncoding.EncodeToString([]byte(fakeProxyCACertData)),
				}
				err := configlib.SetCert(cert)
				Expect(err).To(BeNil())

				certOptions, err := GetRegistryCertOptions(testHost)
				Expect(err).To(BeNil())
				Expect(certOptions).ToNot(BeNil())

				regFilePath, err := configpaths.GetRegistryCertFile()
				Expect(err).To(BeNil())
				Expect(certOptions.CACertPaths).To(ContainElement(regFilePath))
				certData, err := os.ReadFile(regFilePath)
				Expect(err).To(BeNil())
				Expect(string(certData)).To(Equal(fakeCACertData))
				Expect(certOptions.SkipCertVerify).To(Equal(true))
				Expect(certOptions.Insecure).To(Equal(false))
			})
		})

	})

})
