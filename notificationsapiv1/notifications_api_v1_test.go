/**
 * (C) Copyright IBM Corp. 2021.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package notificationsapiv1_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/go-openapi/strfmt"
	"github.com/ibm-cloud-security/security-advisor-sdk-go/v3/notificationsapiv1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe(`NotificationsApiV1`, func() {
	var testServer *httptest.Server
	Describe(`Service constructor tests`, func() {
		It(`Instantiate service client`, func() {
			notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
				Authenticator: &core.NoAuthAuthenticator{},
			})
			Expect(notificationsApiService).ToNot(BeNil())
			Expect(serviceErr).To(BeNil())
		})
		It(`Instantiate service client with error: Invalid URL`, func() {
			notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
				URL: "{BAD_URL_STRING",
			})
			Expect(notificationsApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
		It(`Instantiate service client with error: Invalid Auth`, func() {
			notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
				URL: "https://notificationsapiv1/api",
				Authenticator: &core.BasicAuthenticator{
					Username: "",
					Password: "",
				},
			})
			Expect(notificationsApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
	})
	Describe(`Service constructor tests using external config`, func() {
		Context(`Using external config, construct service client instances`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"NOTIFICATIONS_API_URL":       "https://notificationsapiv1/api",
				"NOTIFICATIONS_API_AUTH_TYPE": "noauth",
			}

			It(`Create service client using external config successfully`, func() {
				SetTestEnvironment(testEnvironment)
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1UsingExternalConfig(&notificationsapiv1.NotificationsApiV1Options{})
				Expect(notificationsApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)

				clone := notificationsApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != notificationsApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(notificationsApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(notificationsApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1UsingExternalConfig(&notificationsapiv1.NotificationsApiV1Options{
					URL: "https://testService/api",
				})
				Expect(notificationsApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := notificationsApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != notificationsApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(notificationsApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(notificationsApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1UsingExternalConfig(&notificationsapiv1.NotificationsApiV1Options{})
				err := notificationsApiService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := notificationsApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != notificationsApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(notificationsApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(notificationsApiService.Service.Options.Authenticator))
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"NOTIFICATIONS_API_URL":       "https://notificationsapiv1/api",
				"NOTIFICATIONS_API_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1UsingExternalConfig(&notificationsapiv1.NotificationsApiV1Options{})

			It(`Instantiate service client with error`, func() {
				Expect(notificationsApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid URL`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"NOTIFICATIONS_API_AUTH_TYPE": "NOAuth",
			}

			SetTestEnvironment(testEnvironment)
			notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1UsingExternalConfig(&notificationsapiv1.NotificationsApiV1Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(notificationsApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})
	Describe(`Regional endpoint tests`, func() {
		It(`GetServiceURLForRegion(region string)`, func() {
			var url string
			var err error
			url, err = notificationsapiv1.GetServiceURLForRegion("INVALID_REGION")
			Expect(url).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			fmt.Fprintf(GinkgoWriter, "Expected error: %s\n", err.Error())
		})
	})
	Describe(`ListAllChannels(listAllChannelsOptions *ListAllChannelsOptions) - Operation response error`, func() {
		listAllChannelsPath := "/v1/testString/notifications/channels"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listAllChannelsPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(38))}))
					Expect(req.URL.Query()["skip"]).To(Equal([]string{fmt.Sprint(int64(38))}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListAllChannels with error: Operation response processing error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the ListAllChannelsOptions model
				listAllChannelsOptionsModel := new(notificationsapiv1.ListAllChannelsOptions)
				listAllChannelsOptionsModel.AccountID = core.StringPtr("testString")
				listAllChannelsOptionsModel.TransactionID = core.StringPtr("testString")
				listAllChannelsOptionsModel.Limit = core.Int64Ptr(int64(38))
				listAllChannelsOptionsModel.Skip = core.Int64Ptr(int64(38))
				listAllChannelsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := notificationsApiService.ListAllChannels(listAllChannelsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				notificationsApiService.EnableRetries(0, 0)
				result, response, operationErr = notificationsApiService.ListAllChannels(listAllChannelsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`ListAllChannels(listAllChannelsOptions *ListAllChannelsOptions)`, func() {
		listAllChannelsPath := "/v1/testString/notifications/channels"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listAllChannelsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(38))}))
					Expect(req.URL.Query()["skip"]).To(Equal([]string{fmt.Sprint(int64(38))}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"channels": [{"channel_id": "ChannelID", "name": "Name", "description": "Description", "type": "Webhook", "severity": {"critical": true, "high": true, "medium": true, "low": false}, "endpoint": "Endpoint", "enabled": false, "alert_source": [{"provider_name": "VA", "finding_types": ["anyValue"]}], "frequency": "Frequency"}]}`)
				}))
			})
			It(`Invoke ListAllChannels successfully with retries`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())
				notificationsApiService.EnableRetries(0, 0)

				// Construct an instance of the ListAllChannelsOptions model
				listAllChannelsOptionsModel := new(notificationsapiv1.ListAllChannelsOptions)
				listAllChannelsOptionsModel.AccountID = core.StringPtr("testString")
				listAllChannelsOptionsModel.TransactionID = core.StringPtr("testString")
				listAllChannelsOptionsModel.Limit = core.Int64Ptr(int64(38))
				listAllChannelsOptionsModel.Skip = core.Int64Ptr(int64(38))
				listAllChannelsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := notificationsApiService.ListAllChannelsWithContext(ctx, listAllChannelsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				notificationsApiService.DisableRetries()
				result, response, operationErr := notificationsApiService.ListAllChannels(listAllChannelsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = notificationsApiService.ListAllChannelsWithContext(ctx, listAllChannelsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listAllChannelsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(38))}))
					Expect(req.URL.Query()["skip"]).To(Equal([]string{fmt.Sprint(int64(38))}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"channels": [{"channel_id": "ChannelID", "name": "Name", "description": "Description", "type": "Webhook", "severity": {"critical": true, "high": true, "medium": true, "low": false}, "endpoint": "Endpoint", "enabled": false, "alert_source": [{"provider_name": "VA", "finding_types": ["anyValue"]}], "frequency": "Frequency"}]}`)
				}))
			})
			It(`Invoke ListAllChannels successfully`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := notificationsApiService.ListAllChannels(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListAllChannelsOptions model
				listAllChannelsOptionsModel := new(notificationsapiv1.ListAllChannelsOptions)
				listAllChannelsOptionsModel.AccountID = core.StringPtr("testString")
				listAllChannelsOptionsModel.TransactionID = core.StringPtr("testString")
				listAllChannelsOptionsModel.Limit = core.Int64Ptr(int64(38))
				listAllChannelsOptionsModel.Skip = core.Int64Ptr(int64(38))
				listAllChannelsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = notificationsApiService.ListAllChannels(listAllChannelsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListAllChannels with error: Operation validation and request error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the ListAllChannelsOptions model
				listAllChannelsOptionsModel := new(notificationsapiv1.ListAllChannelsOptions)
				listAllChannelsOptionsModel.AccountID = core.StringPtr("testString")
				listAllChannelsOptionsModel.TransactionID = core.StringPtr("testString")
				listAllChannelsOptionsModel.Limit = core.Int64Ptr(int64(38))
				listAllChannelsOptionsModel.Skip = core.Int64Ptr(int64(38))
				listAllChannelsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := notificationsApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := notificationsApiService.ListAllChannels(listAllChannelsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the ListAllChannelsOptions model with no property values
				listAllChannelsOptionsModelNew := new(notificationsapiv1.ListAllChannelsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = notificationsApiService.ListAllChannels(listAllChannelsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateNotificationChannel(createNotificationChannelOptions *CreateNotificationChannelOptions) - Operation response error`, func() {
		createNotificationChannelPath := "/v1/testString/notifications/channels"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createNotificationChannelPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateNotificationChannel with error: Operation response processing error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the NotificationChannelAlertSourceItem model
				notificationChannelAlertSourceItemModel := new(notificationsapiv1.NotificationChannelAlertSourceItem)
				notificationChannelAlertSourceItemModel.ProviderName = core.StringPtr("testString")
				notificationChannelAlertSourceItemModel.FindingTypes = []string{"testString"}

				// Construct an instance of the CreateNotificationChannelOptions model
				createNotificationChannelOptionsModel := new(notificationsapiv1.CreateNotificationChannelOptions)
				createNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Name = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Type = core.StringPtr("Webhook")
				createNotificationChannelOptionsModel.Endpoint = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Description = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Severity = []string{"low"}
				createNotificationChannelOptionsModel.Enabled = core.BoolPtr(true)
				createNotificationChannelOptionsModel.AlertSource = []notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel}
				createNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := notificationsApiService.CreateNotificationChannel(createNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				notificationsApiService.EnableRetries(0, 0)
				result, response, operationErr = notificationsApiService.CreateNotificationChannel(createNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`CreateNotificationChannel(createNotificationChannelOptions *CreateNotificationChannelOptions)`, func() {
		createNotificationChannelPath := "/v1/testString/notifications/channels"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createNotificationChannelPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"channel_id": "ChannelID", "status_code": 10}`)
				}))
			})
			It(`Invoke CreateNotificationChannel successfully with retries`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())
				notificationsApiService.EnableRetries(0, 0)

				// Construct an instance of the NotificationChannelAlertSourceItem model
				notificationChannelAlertSourceItemModel := new(notificationsapiv1.NotificationChannelAlertSourceItem)
				notificationChannelAlertSourceItemModel.ProviderName = core.StringPtr("testString")
				notificationChannelAlertSourceItemModel.FindingTypes = []string{"testString"}

				// Construct an instance of the CreateNotificationChannelOptions model
				createNotificationChannelOptionsModel := new(notificationsapiv1.CreateNotificationChannelOptions)
				createNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Name = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Type = core.StringPtr("Webhook")
				createNotificationChannelOptionsModel.Endpoint = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Description = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Severity = []string{"low"}
				createNotificationChannelOptionsModel.Enabled = core.BoolPtr(true)
				createNotificationChannelOptionsModel.AlertSource = []notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel}
				createNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := notificationsApiService.CreateNotificationChannelWithContext(ctx, createNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				notificationsApiService.DisableRetries()
				result, response, operationErr := notificationsApiService.CreateNotificationChannel(createNotificationChannelOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = notificationsApiService.CreateNotificationChannelWithContext(ctx, createNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createNotificationChannelPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"channel_id": "ChannelID", "status_code": 10}`)
				}))
			})
			It(`Invoke CreateNotificationChannel successfully`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := notificationsApiService.CreateNotificationChannel(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the NotificationChannelAlertSourceItem model
				notificationChannelAlertSourceItemModel := new(notificationsapiv1.NotificationChannelAlertSourceItem)
				notificationChannelAlertSourceItemModel.ProviderName = core.StringPtr("testString")
				notificationChannelAlertSourceItemModel.FindingTypes = []string{"testString"}

				// Construct an instance of the CreateNotificationChannelOptions model
				createNotificationChannelOptionsModel := new(notificationsapiv1.CreateNotificationChannelOptions)
				createNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Name = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Type = core.StringPtr("Webhook")
				createNotificationChannelOptionsModel.Endpoint = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Description = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Severity = []string{"low"}
				createNotificationChannelOptionsModel.Enabled = core.BoolPtr(true)
				createNotificationChannelOptionsModel.AlertSource = []notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel}
				createNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = notificationsApiService.CreateNotificationChannel(createNotificationChannelOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateNotificationChannel with error: Operation validation and request error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the NotificationChannelAlertSourceItem model
				notificationChannelAlertSourceItemModel := new(notificationsapiv1.NotificationChannelAlertSourceItem)
				notificationChannelAlertSourceItemModel.ProviderName = core.StringPtr("testString")
				notificationChannelAlertSourceItemModel.FindingTypes = []string{"testString"}

				// Construct an instance of the CreateNotificationChannelOptions model
				createNotificationChannelOptionsModel := new(notificationsapiv1.CreateNotificationChannelOptions)
				createNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Name = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Type = core.StringPtr("Webhook")
				createNotificationChannelOptionsModel.Endpoint = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Description = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Severity = []string{"low"}
				createNotificationChannelOptionsModel.Enabled = core.BoolPtr(true)
				createNotificationChannelOptionsModel.AlertSource = []notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel}
				createNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				createNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := notificationsApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := notificationsApiService.CreateNotificationChannel(createNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateNotificationChannelOptions model with no property values
				createNotificationChannelOptionsModelNew := new(notificationsapiv1.CreateNotificationChannelOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = notificationsApiService.CreateNotificationChannel(createNotificationChannelOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteNotificationChannels(deleteNotificationChannelsOptions *DeleteNotificationChannelsOptions) - Operation response error`, func() {
		deleteNotificationChannelsPath := "/v1/testString/notifications/channels"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteNotificationChannelsPath))
					Expect(req.Method).To(Equal("DELETE"))
					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke DeleteNotificationChannels with error: Operation response processing error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the DeleteNotificationChannelsOptions model
				deleteNotificationChannelsOptionsModel := new(notificationsapiv1.DeleteNotificationChannelsOptions)
				deleteNotificationChannelsOptionsModel.AccountID = core.StringPtr("testString")
				deleteNotificationChannelsOptionsModel.Body = []string{"testString"}
				deleteNotificationChannelsOptionsModel.TransactionID = core.StringPtr("testString")
				deleteNotificationChannelsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := notificationsApiService.DeleteNotificationChannels(deleteNotificationChannelsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				notificationsApiService.EnableRetries(0, 0)
				result, response, operationErr = notificationsApiService.DeleteNotificationChannels(deleteNotificationChannelsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`DeleteNotificationChannels(deleteNotificationChannelsOptions *DeleteNotificationChannelsOptions)`, func() {
		deleteNotificationChannelsPath := "/v1/testString/notifications/channels"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteNotificationChannelsPath))
					Expect(req.Method).To(Equal("DELETE"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"message": "Message"}`)
				}))
			})
			It(`Invoke DeleteNotificationChannels successfully with retries`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())
				notificationsApiService.EnableRetries(0, 0)

				// Construct an instance of the DeleteNotificationChannelsOptions model
				deleteNotificationChannelsOptionsModel := new(notificationsapiv1.DeleteNotificationChannelsOptions)
				deleteNotificationChannelsOptionsModel.AccountID = core.StringPtr("testString")
				deleteNotificationChannelsOptionsModel.Body = []string{"testString"}
				deleteNotificationChannelsOptionsModel.TransactionID = core.StringPtr("testString")
				deleteNotificationChannelsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := notificationsApiService.DeleteNotificationChannelsWithContext(ctx, deleteNotificationChannelsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				notificationsApiService.DisableRetries()
				result, response, operationErr := notificationsApiService.DeleteNotificationChannels(deleteNotificationChannelsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = notificationsApiService.DeleteNotificationChannelsWithContext(ctx, deleteNotificationChannelsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteNotificationChannelsPath))
					Expect(req.Method).To(Equal("DELETE"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"message": "Message"}`)
				}))
			})
			It(`Invoke DeleteNotificationChannels successfully`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := notificationsApiService.DeleteNotificationChannels(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the DeleteNotificationChannelsOptions model
				deleteNotificationChannelsOptionsModel := new(notificationsapiv1.DeleteNotificationChannelsOptions)
				deleteNotificationChannelsOptionsModel.AccountID = core.StringPtr("testString")
				deleteNotificationChannelsOptionsModel.Body = []string{"testString"}
				deleteNotificationChannelsOptionsModel.TransactionID = core.StringPtr("testString")
				deleteNotificationChannelsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = notificationsApiService.DeleteNotificationChannels(deleteNotificationChannelsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke DeleteNotificationChannels with error: Operation validation and request error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the DeleteNotificationChannelsOptions model
				deleteNotificationChannelsOptionsModel := new(notificationsapiv1.DeleteNotificationChannelsOptions)
				deleteNotificationChannelsOptionsModel.AccountID = core.StringPtr("testString")
				deleteNotificationChannelsOptionsModel.Body = []string{"testString"}
				deleteNotificationChannelsOptionsModel.TransactionID = core.StringPtr("testString")
				deleteNotificationChannelsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := notificationsApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := notificationsApiService.DeleteNotificationChannels(deleteNotificationChannelsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the DeleteNotificationChannelsOptions model with no property values
				deleteNotificationChannelsOptionsModelNew := new(notificationsapiv1.DeleteNotificationChannelsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = notificationsApiService.DeleteNotificationChannels(deleteNotificationChannelsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteNotificationChannel(deleteNotificationChannelOptions *DeleteNotificationChannelOptions) - Operation response error`, func() {
		deleteNotificationChannelPath := "/v1/testString/notifications/channels/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteNotificationChannelPath))
					Expect(req.Method).To(Equal("DELETE"))
					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke DeleteNotificationChannel with error: Operation response processing error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the DeleteNotificationChannelOptions model
				deleteNotificationChannelOptionsModel := new(notificationsapiv1.DeleteNotificationChannelOptions)
				deleteNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := notificationsApiService.DeleteNotificationChannel(deleteNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				notificationsApiService.EnableRetries(0, 0)
				result, response, operationErr = notificationsApiService.DeleteNotificationChannel(deleteNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`DeleteNotificationChannel(deleteNotificationChannelOptions *DeleteNotificationChannelOptions)`, func() {
		deleteNotificationChannelPath := "/v1/testString/notifications/channels/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteNotificationChannelPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"channel_id": "ChannelID", "message": "Message"}`)
				}))
			})
			It(`Invoke DeleteNotificationChannel successfully with retries`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())
				notificationsApiService.EnableRetries(0, 0)

				// Construct an instance of the DeleteNotificationChannelOptions model
				deleteNotificationChannelOptionsModel := new(notificationsapiv1.DeleteNotificationChannelOptions)
				deleteNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := notificationsApiService.DeleteNotificationChannelWithContext(ctx, deleteNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				notificationsApiService.DisableRetries()
				result, response, operationErr := notificationsApiService.DeleteNotificationChannel(deleteNotificationChannelOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = notificationsApiService.DeleteNotificationChannelWithContext(ctx, deleteNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteNotificationChannelPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"channel_id": "ChannelID", "message": "Message"}`)
				}))
			})
			It(`Invoke DeleteNotificationChannel successfully`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := notificationsApiService.DeleteNotificationChannel(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the DeleteNotificationChannelOptions model
				deleteNotificationChannelOptionsModel := new(notificationsapiv1.DeleteNotificationChannelOptions)
				deleteNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = notificationsApiService.DeleteNotificationChannel(deleteNotificationChannelOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke DeleteNotificationChannel with error: Operation validation and request error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the DeleteNotificationChannelOptions model
				deleteNotificationChannelOptionsModel := new(notificationsapiv1.DeleteNotificationChannelOptions)
				deleteNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				deleteNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := notificationsApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := notificationsApiService.DeleteNotificationChannel(deleteNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the DeleteNotificationChannelOptions model with no property values
				deleteNotificationChannelOptionsModelNew := new(notificationsapiv1.DeleteNotificationChannelOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = notificationsApiService.DeleteNotificationChannel(deleteNotificationChannelOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetNotificationChannel(getNotificationChannelOptions *GetNotificationChannelOptions) - Operation response error`, func() {
		getNotificationChannelPath := "/v1/testString/notifications/channels/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getNotificationChannelPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetNotificationChannel with error: Operation response processing error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the GetNotificationChannelOptions model
				getNotificationChannelOptionsModel := new(notificationsapiv1.GetNotificationChannelOptions)
				getNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := notificationsApiService.GetNotificationChannel(getNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				notificationsApiService.EnableRetries(0, 0)
				result, response, operationErr = notificationsApiService.GetNotificationChannel(getNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`GetNotificationChannel(getNotificationChannelOptions *GetNotificationChannelOptions)`, func() {
		getNotificationChannelPath := "/v1/testString/notifications/channels/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getNotificationChannelPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"channel": {"channel_id": "ChannelID", "name": "Name", "description": "Description", "type": "Webhook", "severity": {"critical": true, "high": true, "medium": true, "low": false}, "endpoint": "Endpoint", "enabled": false, "alert_source": [{"provider_name": "VA", "finding_types": ["anyValue"]}], "frequency": "Frequency"}}`)
				}))
			})
			It(`Invoke GetNotificationChannel successfully with retries`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())
				notificationsApiService.EnableRetries(0, 0)

				// Construct an instance of the GetNotificationChannelOptions model
				getNotificationChannelOptionsModel := new(notificationsapiv1.GetNotificationChannelOptions)
				getNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := notificationsApiService.GetNotificationChannelWithContext(ctx, getNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				notificationsApiService.DisableRetries()
				result, response, operationErr := notificationsApiService.GetNotificationChannel(getNotificationChannelOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = notificationsApiService.GetNotificationChannelWithContext(ctx, getNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getNotificationChannelPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"channel": {"channel_id": "ChannelID", "name": "Name", "description": "Description", "type": "Webhook", "severity": {"critical": true, "high": true, "medium": true, "low": false}, "endpoint": "Endpoint", "enabled": false, "alert_source": [{"provider_name": "VA", "finding_types": ["anyValue"]}], "frequency": "Frequency"}}`)
				}))
			})
			It(`Invoke GetNotificationChannel successfully`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := notificationsApiService.GetNotificationChannel(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetNotificationChannelOptions model
				getNotificationChannelOptionsModel := new(notificationsapiv1.GetNotificationChannelOptions)
				getNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = notificationsApiService.GetNotificationChannel(getNotificationChannelOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetNotificationChannel with error: Operation validation and request error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the GetNotificationChannelOptions model
				getNotificationChannelOptionsModel := new(notificationsapiv1.GetNotificationChannelOptions)
				getNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				getNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := notificationsApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := notificationsApiService.GetNotificationChannel(getNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetNotificationChannelOptions model with no property values
				getNotificationChannelOptionsModelNew := new(notificationsapiv1.GetNotificationChannelOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = notificationsApiService.GetNotificationChannel(getNotificationChannelOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UpdateNotificationChannel(updateNotificationChannelOptions *UpdateNotificationChannelOptions) - Operation response error`, func() {
		updateNotificationChannelPath := "/v1/testString/notifications/channels/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateNotificationChannelPath))
					Expect(req.Method).To(Equal("PUT"))
					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UpdateNotificationChannel with error: Operation response processing error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the NotificationChannelAlertSourceItem model
				notificationChannelAlertSourceItemModel := new(notificationsapiv1.NotificationChannelAlertSourceItem)
				notificationChannelAlertSourceItemModel.ProviderName = core.StringPtr("testString")
				notificationChannelAlertSourceItemModel.FindingTypes = []string{"testString"}

				// Construct an instance of the UpdateNotificationChannelOptions model
				updateNotificationChannelOptionsModel := new(notificationsapiv1.UpdateNotificationChannelOptions)
				updateNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Name = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Type = core.StringPtr("Webhook")
				updateNotificationChannelOptionsModel.Endpoint = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Description = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Severity = []string{"low"}
				updateNotificationChannelOptionsModel.Enabled = core.BoolPtr(true)
				updateNotificationChannelOptionsModel.AlertSource = []notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel}
				updateNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := notificationsApiService.UpdateNotificationChannel(updateNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				notificationsApiService.EnableRetries(0, 0)
				result, response, operationErr = notificationsApiService.UpdateNotificationChannel(updateNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`UpdateNotificationChannel(updateNotificationChannelOptions *UpdateNotificationChannelOptions)`, func() {
		updateNotificationChannelPath := "/v1/testString/notifications/channels/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateNotificationChannelPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"channel_id": "ChannelID", "status_code": 10}`)
				}))
			})
			It(`Invoke UpdateNotificationChannel successfully with retries`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())
				notificationsApiService.EnableRetries(0, 0)

				// Construct an instance of the NotificationChannelAlertSourceItem model
				notificationChannelAlertSourceItemModel := new(notificationsapiv1.NotificationChannelAlertSourceItem)
				notificationChannelAlertSourceItemModel.ProviderName = core.StringPtr("testString")
				notificationChannelAlertSourceItemModel.FindingTypes = []string{"testString"}

				// Construct an instance of the UpdateNotificationChannelOptions model
				updateNotificationChannelOptionsModel := new(notificationsapiv1.UpdateNotificationChannelOptions)
				updateNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Name = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Type = core.StringPtr("Webhook")
				updateNotificationChannelOptionsModel.Endpoint = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Description = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Severity = []string{"low"}
				updateNotificationChannelOptionsModel.Enabled = core.BoolPtr(true)
				updateNotificationChannelOptionsModel.AlertSource = []notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel}
				updateNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := notificationsApiService.UpdateNotificationChannelWithContext(ctx, updateNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				notificationsApiService.DisableRetries()
				result, response, operationErr := notificationsApiService.UpdateNotificationChannel(updateNotificationChannelOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = notificationsApiService.UpdateNotificationChannelWithContext(ctx, updateNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(updateNotificationChannelPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"channel_id": "ChannelID", "status_code": 10}`)
				}))
			})
			It(`Invoke UpdateNotificationChannel successfully`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := notificationsApiService.UpdateNotificationChannel(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the NotificationChannelAlertSourceItem model
				notificationChannelAlertSourceItemModel := new(notificationsapiv1.NotificationChannelAlertSourceItem)
				notificationChannelAlertSourceItemModel.ProviderName = core.StringPtr("testString")
				notificationChannelAlertSourceItemModel.FindingTypes = []string{"testString"}

				// Construct an instance of the UpdateNotificationChannelOptions model
				updateNotificationChannelOptionsModel := new(notificationsapiv1.UpdateNotificationChannelOptions)
				updateNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Name = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Type = core.StringPtr("Webhook")
				updateNotificationChannelOptionsModel.Endpoint = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Description = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Severity = []string{"low"}
				updateNotificationChannelOptionsModel.Enabled = core.BoolPtr(true)
				updateNotificationChannelOptionsModel.AlertSource = []notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel}
				updateNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = notificationsApiService.UpdateNotificationChannel(updateNotificationChannelOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UpdateNotificationChannel with error: Operation validation and request error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the NotificationChannelAlertSourceItem model
				notificationChannelAlertSourceItemModel := new(notificationsapiv1.NotificationChannelAlertSourceItem)
				notificationChannelAlertSourceItemModel.ProviderName = core.StringPtr("testString")
				notificationChannelAlertSourceItemModel.FindingTypes = []string{"testString"}

				// Construct an instance of the UpdateNotificationChannelOptions model
				updateNotificationChannelOptionsModel := new(notificationsapiv1.UpdateNotificationChannelOptions)
				updateNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Name = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Type = core.StringPtr("Webhook")
				updateNotificationChannelOptionsModel.Endpoint = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Description = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Severity = []string{"low"}
				updateNotificationChannelOptionsModel.Enabled = core.BoolPtr(true)
				updateNotificationChannelOptionsModel.AlertSource = []notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel}
				updateNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				updateNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := notificationsApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := notificationsApiService.UpdateNotificationChannel(updateNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UpdateNotificationChannelOptions model with no property values
				updateNotificationChannelOptionsModelNew := new(notificationsapiv1.UpdateNotificationChannelOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = notificationsApiService.UpdateNotificationChannel(updateNotificationChannelOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`TestNotificationChannel(testNotificationChannelOptions *TestNotificationChannelOptions) - Operation response error`, func() {
		testNotificationChannelPath := "/v1/testString/notifications/channels/testString/test"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(testNotificationChannelPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke TestNotificationChannel with error: Operation response processing error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the TestNotificationChannelOptions model
				testNotificationChannelOptionsModel := new(notificationsapiv1.TestNotificationChannelOptions)
				testNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := notificationsApiService.TestNotificationChannel(testNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				notificationsApiService.EnableRetries(0, 0)
				result, response, operationErr = notificationsApiService.TestNotificationChannel(testNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`TestNotificationChannel(testNotificationChannelOptions *TestNotificationChannelOptions)`, func() {
		testNotificationChannelPath := "/v1/testString/notifications/channels/testString/test"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(testNotificationChannelPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"test": "Test"}`)
				}))
			})
			It(`Invoke TestNotificationChannel successfully with retries`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())
				notificationsApiService.EnableRetries(0, 0)

				// Construct an instance of the TestNotificationChannelOptions model
				testNotificationChannelOptionsModel := new(notificationsapiv1.TestNotificationChannelOptions)
				testNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := notificationsApiService.TestNotificationChannelWithContext(ctx, testNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				notificationsApiService.DisableRetries()
				result, response, operationErr := notificationsApiService.TestNotificationChannel(testNotificationChannelOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = notificationsApiService.TestNotificationChannelWithContext(ctx, testNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(testNotificationChannelPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"test": "Test"}`)
				}))
			})
			It(`Invoke TestNotificationChannel successfully`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := notificationsApiService.TestNotificationChannel(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the TestNotificationChannelOptions model
				testNotificationChannelOptionsModel := new(notificationsapiv1.TestNotificationChannelOptions)
				testNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = notificationsApiService.TestNotificationChannel(testNotificationChannelOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke TestNotificationChannel with error: Operation validation and request error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the TestNotificationChannelOptions model
				testNotificationChannelOptionsModel := new(notificationsapiv1.TestNotificationChannelOptions)
				testNotificationChannelOptionsModel.AccountID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.ChannelID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.TransactionID = core.StringPtr("testString")
				testNotificationChannelOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := notificationsApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := notificationsApiService.TestNotificationChannel(testNotificationChannelOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the TestNotificationChannelOptions model with no property values
				testNotificationChannelOptionsModelNew := new(notificationsapiv1.TestNotificationChannelOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = notificationsApiService.TestNotificationChannel(testNotificationChannelOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetPublicKey(getPublicKeyOptions *GetPublicKeyOptions) - Operation response error`, func() {
		getPublicKeyPath := "/v1/testString/notifications/public_key"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPublicKeyPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetPublicKey with error: Operation response processing error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the GetPublicKeyOptions model
				getPublicKeyOptionsModel := new(notificationsapiv1.GetPublicKeyOptions)
				getPublicKeyOptionsModel.AccountID = core.StringPtr("testString")
				getPublicKeyOptionsModel.TransactionID = core.StringPtr("testString")
				getPublicKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := notificationsApiService.GetPublicKey(getPublicKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				notificationsApiService.EnableRetries(0, 0)
				result, response, operationErr = notificationsApiService.GetPublicKey(getPublicKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`GetPublicKey(getPublicKeyOptions *GetPublicKeyOptions)`, func() {
		getPublicKeyPath := "/v1/testString/notifications/public_key"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPublicKeyPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"public_key": "PublicKey"}`)
				}))
			})
			It(`Invoke GetPublicKey successfully with retries`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())
				notificationsApiService.EnableRetries(0, 0)

				// Construct an instance of the GetPublicKeyOptions model
				getPublicKeyOptionsModel := new(notificationsapiv1.GetPublicKeyOptions)
				getPublicKeyOptionsModel.AccountID = core.StringPtr("testString")
				getPublicKeyOptionsModel.TransactionID = core.StringPtr("testString")
				getPublicKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := notificationsApiService.GetPublicKeyWithContext(ctx, getPublicKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				notificationsApiService.DisableRetries()
				result, response, operationErr := notificationsApiService.GetPublicKey(getPublicKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = notificationsApiService.GetPublicKeyWithContext(ctx, getPublicKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPublicKeyPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Transaction-Id"]).ToNot(BeNil())
					Expect(req.Header["Transaction-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"public_key": "PublicKey"}`)
				}))
			})
			It(`Invoke GetPublicKey successfully`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := notificationsApiService.GetPublicKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetPublicKeyOptions model
				getPublicKeyOptionsModel := new(notificationsapiv1.GetPublicKeyOptions)
				getPublicKeyOptionsModel.AccountID = core.StringPtr("testString")
				getPublicKeyOptionsModel.TransactionID = core.StringPtr("testString")
				getPublicKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = notificationsApiService.GetPublicKey(getPublicKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetPublicKey with error: Operation validation and request error`, func() {
				notificationsApiService, serviceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(notificationsApiService).ToNot(BeNil())

				// Construct an instance of the GetPublicKeyOptions model
				getPublicKeyOptionsModel := new(notificationsapiv1.GetPublicKeyOptions)
				getPublicKeyOptionsModel.AccountID = core.StringPtr("testString")
				getPublicKeyOptionsModel.TransactionID = core.StringPtr("testString")
				getPublicKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := notificationsApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := notificationsApiService.GetPublicKey(getPublicKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetPublicKeyOptions model with no property values
				getPublicKeyOptionsModelNew := new(notificationsapiv1.GetPublicKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = notificationsApiService.GetPublicKey(getPublicKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`Model constructor tests`, func() {
		Context(`Using a service client instance`, func() {
			notificationsApiService, _ := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
				URL:           "http://notificationsapiv1modelgenerator.com",
				Authenticator: &core.NoAuthAuthenticator{},
			})
			It(`Invoke NewCreateNotificationChannelOptions successfully`, func() {
				// Construct an instance of the NotificationChannelAlertSourceItem model
				notificationChannelAlertSourceItemModel := new(notificationsapiv1.NotificationChannelAlertSourceItem)
				Expect(notificationChannelAlertSourceItemModel).ToNot(BeNil())
				notificationChannelAlertSourceItemModel.ProviderName = core.StringPtr("testString")
				notificationChannelAlertSourceItemModel.FindingTypes = []string{"testString"}
				Expect(notificationChannelAlertSourceItemModel.ProviderName).To(Equal(core.StringPtr("testString")))
				Expect(notificationChannelAlertSourceItemModel.FindingTypes).To(Equal([]string{"testString"}))

				// Construct an instance of the CreateNotificationChannelOptions model
				accountID := "testString"
				createNotificationChannelOptionsName := "testString"
				createNotificationChannelOptionsType := "Webhook"
				createNotificationChannelOptionsEndpoint := "testString"
				createNotificationChannelOptionsModel := notificationsApiService.NewCreateNotificationChannelOptions(accountID, createNotificationChannelOptionsName, createNotificationChannelOptionsType, createNotificationChannelOptionsEndpoint)
				createNotificationChannelOptionsModel.SetAccountID("testString")
				createNotificationChannelOptionsModel.SetName("testString")
				createNotificationChannelOptionsModel.SetType("Webhook")
				createNotificationChannelOptionsModel.SetEndpoint("testString")
				createNotificationChannelOptionsModel.SetDescription("testString")
				createNotificationChannelOptionsModel.SetSeverity([]string{"low"})
				createNotificationChannelOptionsModel.SetEnabled(true)
				createNotificationChannelOptionsModel.SetAlertSource([]notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel})
				createNotificationChannelOptionsModel.SetTransactionID("testString")
				createNotificationChannelOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createNotificationChannelOptionsModel).ToNot(BeNil())
				Expect(createNotificationChannelOptionsModel.AccountID).To(Equal(core.StringPtr("testString")))
				Expect(createNotificationChannelOptionsModel.Name).To(Equal(core.StringPtr("testString")))
				Expect(createNotificationChannelOptionsModel.Type).To(Equal(core.StringPtr("Webhook")))
				Expect(createNotificationChannelOptionsModel.Endpoint).To(Equal(core.StringPtr("testString")))
				Expect(createNotificationChannelOptionsModel.Description).To(Equal(core.StringPtr("testString")))
				Expect(createNotificationChannelOptionsModel.Severity).To(Equal([]string{"low"}))
				Expect(createNotificationChannelOptionsModel.Enabled).To(Equal(core.BoolPtr(true)))
				Expect(createNotificationChannelOptionsModel.AlertSource).To(Equal([]notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel}))
				Expect(createNotificationChannelOptionsModel.TransactionID).To(Equal(core.StringPtr("testString")))
				Expect(createNotificationChannelOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteNotificationChannelOptions successfully`, func() {
				// Construct an instance of the DeleteNotificationChannelOptions model
				accountID := "testString"
				channelID := "testString"
				deleteNotificationChannelOptionsModel := notificationsApiService.NewDeleteNotificationChannelOptions(accountID, channelID)
				deleteNotificationChannelOptionsModel.SetAccountID("testString")
				deleteNotificationChannelOptionsModel.SetChannelID("testString")
				deleteNotificationChannelOptionsModel.SetTransactionID("testString")
				deleteNotificationChannelOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteNotificationChannelOptionsModel).ToNot(BeNil())
				Expect(deleteNotificationChannelOptionsModel.AccountID).To(Equal(core.StringPtr("testString")))
				Expect(deleteNotificationChannelOptionsModel.ChannelID).To(Equal(core.StringPtr("testString")))
				Expect(deleteNotificationChannelOptionsModel.TransactionID).To(Equal(core.StringPtr("testString")))
				Expect(deleteNotificationChannelOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteNotificationChannelsOptions successfully`, func() {
				// Construct an instance of the DeleteNotificationChannelsOptions model
				accountID := "testString"
				body := []string{"testString"}
				deleteNotificationChannelsOptionsModel := notificationsApiService.NewDeleteNotificationChannelsOptions(accountID, body)
				deleteNotificationChannelsOptionsModel.SetAccountID("testString")
				deleteNotificationChannelsOptionsModel.SetBody([]string{"testString"})
				deleteNotificationChannelsOptionsModel.SetTransactionID("testString")
				deleteNotificationChannelsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteNotificationChannelsOptionsModel).ToNot(BeNil())
				Expect(deleteNotificationChannelsOptionsModel.AccountID).To(Equal(core.StringPtr("testString")))
				Expect(deleteNotificationChannelsOptionsModel.Body).To(Equal([]string{"testString"}))
				Expect(deleteNotificationChannelsOptionsModel.TransactionID).To(Equal(core.StringPtr("testString")))
				Expect(deleteNotificationChannelsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetNotificationChannelOptions successfully`, func() {
				// Construct an instance of the GetNotificationChannelOptions model
				accountID := "testString"
				channelID := "testString"
				getNotificationChannelOptionsModel := notificationsApiService.NewGetNotificationChannelOptions(accountID, channelID)
				getNotificationChannelOptionsModel.SetAccountID("testString")
				getNotificationChannelOptionsModel.SetChannelID("testString")
				getNotificationChannelOptionsModel.SetTransactionID("testString")
				getNotificationChannelOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getNotificationChannelOptionsModel).ToNot(BeNil())
				Expect(getNotificationChannelOptionsModel.AccountID).To(Equal(core.StringPtr("testString")))
				Expect(getNotificationChannelOptionsModel.ChannelID).To(Equal(core.StringPtr("testString")))
				Expect(getNotificationChannelOptionsModel.TransactionID).To(Equal(core.StringPtr("testString")))
				Expect(getNotificationChannelOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetPublicKeyOptions successfully`, func() {
				// Construct an instance of the GetPublicKeyOptions model
				accountID := "testString"
				getPublicKeyOptionsModel := notificationsApiService.NewGetPublicKeyOptions(accountID)
				getPublicKeyOptionsModel.SetAccountID("testString")
				getPublicKeyOptionsModel.SetTransactionID("testString")
				getPublicKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getPublicKeyOptionsModel).ToNot(BeNil())
				Expect(getPublicKeyOptionsModel.AccountID).To(Equal(core.StringPtr("testString")))
				Expect(getPublicKeyOptionsModel.TransactionID).To(Equal(core.StringPtr("testString")))
				Expect(getPublicKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewListAllChannelsOptions successfully`, func() {
				// Construct an instance of the ListAllChannelsOptions model
				accountID := "testString"
				listAllChannelsOptionsModel := notificationsApiService.NewListAllChannelsOptions(accountID)
				listAllChannelsOptionsModel.SetAccountID("testString")
				listAllChannelsOptionsModel.SetTransactionID("testString")
				listAllChannelsOptionsModel.SetLimit(int64(38))
				listAllChannelsOptionsModel.SetSkip(int64(38))
				listAllChannelsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listAllChannelsOptionsModel).ToNot(BeNil())
				Expect(listAllChannelsOptionsModel.AccountID).To(Equal(core.StringPtr("testString")))
				Expect(listAllChannelsOptionsModel.TransactionID).To(Equal(core.StringPtr("testString")))
				Expect(listAllChannelsOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(38))))
				Expect(listAllChannelsOptionsModel.Skip).To(Equal(core.Int64Ptr(int64(38))))
				Expect(listAllChannelsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewNotificationChannelAlertSourceItem successfully`, func() {
				providerName := "testString"
				model, err := notificationsApiService.NewNotificationChannelAlertSourceItem(providerName)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewTestNotificationChannelOptions successfully`, func() {
				// Construct an instance of the TestNotificationChannelOptions model
				accountID := "testString"
				channelID := "testString"
				testNotificationChannelOptionsModel := notificationsApiService.NewTestNotificationChannelOptions(accountID, channelID)
				testNotificationChannelOptionsModel.SetAccountID("testString")
				testNotificationChannelOptionsModel.SetChannelID("testString")
				testNotificationChannelOptionsModel.SetTransactionID("testString")
				testNotificationChannelOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(testNotificationChannelOptionsModel).ToNot(BeNil())
				Expect(testNotificationChannelOptionsModel.AccountID).To(Equal(core.StringPtr("testString")))
				Expect(testNotificationChannelOptionsModel.ChannelID).To(Equal(core.StringPtr("testString")))
				Expect(testNotificationChannelOptionsModel.TransactionID).To(Equal(core.StringPtr("testString")))
				Expect(testNotificationChannelOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUpdateNotificationChannelOptions successfully`, func() {
				// Construct an instance of the NotificationChannelAlertSourceItem model
				notificationChannelAlertSourceItemModel := new(notificationsapiv1.NotificationChannelAlertSourceItem)
				Expect(notificationChannelAlertSourceItemModel).ToNot(BeNil())
				notificationChannelAlertSourceItemModel.ProviderName = core.StringPtr("testString")
				notificationChannelAlertSourceItemModel.FindingTypes = []string{"testString"}
				Expect(notificationChannelAlertSourceItemModel.ProviderName).To(Equal(core.StringPtr("testString")))
				Expect(notificationChannelAlertSourceItemModel.FindingTypes).To(Equal([]string{"testString"}))

				// Construct an instance of the UpdateNotificationChannelOptions model
				accountID := "testString"
				channelID := "testString"
				updateNotificationChannelOptionsName := "testString"
				updateNotificationChannelOptionsType := "Webhook"
				updateNotificationChannelOptionsEndpoint := "testString"
				updateNotificationChannelOptionsModel := notificationsApiService.NewUpdateNotificationChannelOptions(accountID, channelID, updateNotificationChannelOptionsName, updateNotificationChannelOptionsType, updateNotificationChannelOptionsEndpoint)
				updateNotificationChannelOptionsModel.SetAccountID("testString")
				updateNotificationChannelOptionsModel.SetChannelID("testString")
				updateNotificationChannelOptionsModel.SetName("testString")
				updateNotificationChannelOptionsModel.SetType("Webhook")
				updateNotificationChannelOptionsModel.SetEndpoint("testString")
				updateNotificationChannelOptionsModel.SetDescription("testString")
				updateNotificationChannelOptionsModel.SetSeverity([]string{"low"})
				updateNotificationChannelOptionsModel.SetEnabled(true)
				updateNotificationChannelOptionsModel.SetAlertSource([]notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel})
				updateNotificationChannelOptionsModel.SetTransactionID("testString")
				updateNotificationChannelOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(updateNotificationChannelOptionsModel).ToNot(BeNil())
				Expect(updateNotificationChannelOptionsModel.AccountID).To(Equal(core.StringPtr("testString")))
				Expect(updateNotificationChannelOptionsModel.ChannelID).To(Equal(core.StringPtr("testString")))
				Expect(updateNotificationChannelOptionsModel.Name).To(Equal(core.StringPtr("testString")))
				Expect(updateNotificationChannelOptionsModel.Type).To(Equal(core.StringPtr("Webhook")))
				Expect(updateNotificationChannelOptionsModel.Endpoint).To(Equal(core.StringPtr("testString")))
				Expect(updateNotificationChannelOptionsModel.Description).To(Equal(core.StringPtr("testString")))
				Expect(updateNotificationChannelOptionsModel.Severity).To(Equal([]string{"low"}))
				Expect(updateNotificationChannelOptionsModel.Enabled).To(Equal(core.BoolPtr(true)))
				Expect(updateNotificationChannelOptionsModel.AlertSource).To(Equal([]notificationsapiv1.NotificationChannelAlertSourceItem{*notificationChannelAlertSourceItemModel}))
				Expect(updateNotificationChannelOptionsModel.TransactionID).To(Equal(core.StringPtr("testString")))
				Expect(updateNotificationChannelOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
		})
	})
	Describe(`Utility function tests`, func() {
		It(`Invoke CreateMockByteArray() successfully`, func() {
			mockByteArray := CreateMockByteArray("This is a test")
			Expect(mockByteArray).ToNot(BeNil())
		})
		It(`Invoke CreateMockUUID() successfully`, func() {
			mockUUID := CreateMockUUID("9fab83da-98cb-4f18-a7ba-b6f0435c9673")
			Expect(mockUUID).ToNot(BeNil())
		})
		It(`Invoke CreateMockReader() successfully`, func() {
			mockReader := CreateMockReader("This is a test.")
			Expect(mockReader).ToNot(BeNil())
		})
		It(`Invoke CreateMockDate() successfully`, func() {
			mockDate := CreateMockDate()
			Expect(mockDate).ToNot(BeNil())
		})
		It(`Invoke CreateMockDateTime() successfully`, func() {
			mockDateTime := CreateMockDateTime()
			Expect(mockDateTime).ToNot(BeNil())
		})
	})
})

//
// Utility functions used by the generated test code
//

func CreateMockByteArray(mockData string) *[]byte {
	ba := make([]byte, 0)
	ba = append(ba, mockData...)
	return &ba
}

func CreateMockUUID(mockData string) *strfmt.UUID {
	uuid := strfmt.UUID(mockData)
	return &uuid
}

func CreateMockReader(mockData string) io.ReadCloser {
	return ioutil.NopCloser(bytes.NewReader([]byte(mockData)))
}

func CreateMockDate() *strfmt.Date {
	d := strfmt.Date(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC))
	return &d
}

func CreateMockDateTime() *strfmt.DateTime {
	d := strfmt.DateTime(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC))
	return &d
}

func SetTestEnvironment(testEnvironment map[string]string) {
	for key, value := range testEnvironment {
		os.Setenv(key, value)
	}
}

func ClearTestEnvironment(testEnvironment map[string]string) {
	for key := range testEnvironment {
		os.Unsetenv(key)
	}
}
