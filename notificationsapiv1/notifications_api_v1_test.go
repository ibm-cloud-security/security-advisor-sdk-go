/**
 * (C) Copyright IBM Corp. 2020.
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/IBM/go-sdk-core/v3/core"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ibm-cloud-security/security-advisor-sdk-go/notificationsapiv1"
)

var _ = Describe(`NotificationsApiV1`, func() {
	Describe(`ListAllChannels(listAllChannelsOptions *ListAllChannelsOptions)`, func() {
		listAllChannelsPath := "/v1/{account_id}/notifications/channels"
		accountID := "exampleString"
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		listAllChannelsPath = strings.Replace(listAllChannelsPath, "{account_id}", accountID, 1)
		Context(`Successfully - list all channels`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(listAllChannelsPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call ListAllChannels`, func() {
				defer testServer.Close()

				testService, testServiceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.ListAllChannels(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//pass Invalid/null values in options
				var listOptions notificationsapiv1.ListAllChannelsOptions
				result, response, operationErr = testService.ListAllChannels(&listOptions)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				listAllChannelsOptions := testService.NewListAllChannelsOptions(accountID)
				listAllChannelsOptions.SetAccountID(accountID)
				listAllChannelsOptions.SetLimit(2)
				listAllChannelsOptions.SetSkip(5)
				listAllChannelsOptions.SetHeaders(headers)
				result, response, operationErr = testService.ListAllChannels(listAllChannelsOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`CreateNotificationChannel(createNotificationChannelOptions *CreateNotificationChannelOptions)`, func() {
		createNotificationChannelPath := "/v1/{account_id}/notifications/channels"
		accountID := "exampleString"
		name := "exampleString"
		typeVar := "exampleString"
		endpoint := "exampleString"
		severity := []string{"low"}
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		createNotificationChannelPath = strings.Replace(createNotificationChannelPath, "{account_id}", accountID, 1)
		Context(`Successfully - create notification channel`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(createNotificationChannelPath))
				Expect(req.Method).To(Equal("POST"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call CreateNotificationChannel`, func() {
				defer testServer.Close()

				testService, testServiceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.CreateNotificationChannel(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//pass Invalid/nil values in options
				var createOptions notificationsapiv1.CreateNotificationChannelOptions
				result, response, operationErr = testService.CreateNotificationChannel(&createOptions)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//Pass required keys
				createNotificationChannelOptions := testService.NewCreateNotificationChannelOptions(accountID, name, typeVar, endpoint)
				result, response, operationErr = testService.CreateNotificationChannel(createNotificationChannelOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				//Pass all keys
				var alertSource []notificationsapiv1.NotificationChannelAlertSourceItem
				source, _ := testService.NewNotificationChannelAlertSourceItem("ATA")
				source.FindingTypes = []string{"iks", "kms"}
				alertSource = append(alertSource, *source)

				createNotificationChannelOptions = testService.NewCreateNotificationChannelOptions(accountID, name, typeVar, endpoint)
				createNotificationChannelOptions.SetHeaders(headers)
				createNotificationChannelOptions.SetDescription("desc")
				Expect(*createNotificationChannelOptions.Description).To(Equal("desc"))
				createNotificationChannelOptions.SetSeverity(severity)
				Expect(createNotificationChannelOptions.Severity[0]).To(Equal("low"))
				createNotificationChannelOptions.SetEnabled(true)
				Expect(*createNotificationChannelOptions.Enabled).To(Equal(true))
				createNotificationChannelOptions.SetAlertSource(alertSource)
				result, response, operationErr = testService.CreateNotificationChannel(createNotificationChannelOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})

			It(`Succeed to call NewCreateNotificationChannelOptions set attributes`, func() {
				defer testServer.Close()

				testService, testServiceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				var alertSource []notificationsapiv1.NotificationChannelAlertSourceItem
				source, _ := testService.NewNotificationChannelAlertSourceItem("ATA")
				source.FindingTypes = []string{"iks", "kms"}
				alertSource = append(alertSource, *source)

				var createNotificationChannelOptions notificationsapiv1.CreateNotificationChannelOptions
				createNotificationChannelOptions.SetAccountID("accountID")
				Expect(*createNotificationChannelOptions.AccountID).To(Equal("accountID"))
				createNotificationChannelOptions.SetName("name")
				Expect(*createNotificationChannelOptions.Name).To(Equal("name"))
				createNotificationChannelOptions.SetType("test")
				Expect(*createNotificationChannelOptions.Type).To(Equal("test"))
				createNotificationChannelOptions.SetEndpoint("endpoint")
				Expect(*createNotificationChannelOptions.Endpoint).To(Equal("endpoint"))
				createNotificationChannelOptions.SetDescription("desc")
				Expect(*createNotificationChannelOptions.Description).To(Equal("desc"))
				createNotificationChannelOptions.SetSeverity(severity)
				Expect(createNotificationChannelOptions.Severity[0]).To(Equal("low"))
				createNotificationChannelOptions.SetEnabled(true)
				Expect(*createNotificationChannelOptions.Enabled).To(Equal(true))
				createNotificationChannelOptions.SetAlertSource(alertSource)
				Expect(*createNotificationChannelOptions.AlertSource[0].ProviderName).To(Equal("ATA"))
				createNotificationChannelOptions.SetHeaders(headers)
			})
		})
	})
	Describe(`DeleteNotificationChannels(deleteNotificationChannelsOptions *DeleteNotificationChannelsOptions)`, func() {
		deleteNotificationChannelsPath := "/v1/{account_id}/notifications/channels"
		accountID := "exampleString"
		body := []string{}
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		deleteNotificationChannelsPath = strings.Replace(deleteNotificationChannelsPath, "{account_id}", accountID, 1)
		Context(`Successfully - bulk delete of channels`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(deleteNotificationChannelsPath))
				Expect(req.Method).To(Equal("DELETE"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call DeleteNotificationChannels`, func() {
				defer testServer.Close()

				testService, testServiceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.DeleteNotificationChannels(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//pass Invalid/nil values in options
				var deleteOptions notificationsapiv1.DeleteNotificationChannelsOptions
				result, response, operationErr = testService.DeleteNotificationChannels(&deleteOptions)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				deleteNotificationChannelsOptions := testService.NewDeleteNotificationChannelsOptions(accountID, body)
				deleteNotificationChannelsOptions.SetBody([]string{"1"})
				deleteNotificationChannelsOptions.SetHeaders(headers)
				deleteNotificationChannelsOptions.SetAccountID(accountID)
				result, response, operationErr = testService.DeleteNotificationChannels(deleteNotificationChannelsOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`DeleteNotificationChannel(deleteNotificationChannelOptions *DeleteNotificationChannelOptions)`, func() {
		deleteNotificationChannelPath := "/v1/{account_id}/notifications/channels/{channel_id}"
		accountID := "exampleString"
		channelID := "exampleString"
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		deleteNotificationChannelPath = strings.Replace(deleteNotificationChannelPath, "{account_id}", accountID, 1)
		deleteNotificationChannelPath = strings.Replace(deleteNotificationChannelPath, "{channel_id}", channelID, 1)
		Context(`Successfully - delete the details of a specific channel`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(deleteNotificationChannelPath))
				Expect(req.Method).To(Equal("DELETE"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call DeleteNotificationChannel`, func() {
				defer testServer.Close()

				testService, testServiceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.DeleteNotificationChannel(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//pass Invalid/nil values in options
				var deleteOptions notificationsapiv1.DeleteNotificationChannelOptions
				result, response, operationErr = testService.DeleteNotificationChannel(&deleteOptions)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				deleteNotificationChannelOptions := testService.NewDeleteNotificationChannelOptions(accountID, channelID)
				deleteNotificationChannelOptions.SetChannelID(channelID)
				deleteNotificationChannelOptions.SetHeaders(headers)
				deleteNotificationChannelOptions.SetAccountID(accountID)
				result, response, operationErr = testService.DeleteNotificationChannel(deleteNotificationChannelOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetNotificationChannel(getNotificationChannelOptions *GetNotificationChannelOptions)`, func() {
		getNotificationChannelPath := "/v1/{account_id}/notifications/channels/{channel_id}"
		accountID := "exampleString"
		channelID := "exampleString"
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		getNotificationChannelPath = strings.Replace(getNotificationChannelPath, "{account_id}", accountID, 1)
		getNotificationChannelPath = strings.Replace(getNotificationChannelPath, "{channel_id}", channelID, 1)
		Context(`Successfully - get the details of a specific channel`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getNotificationChannelPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call GetNotificationChannel`, func() {
				defer testServer.Close()

				testService, testServiceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.GetNotificationChannel(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//pass Invalid/nil values in options
				var getOptions notificationsapiv1.GetNotificationChannelOptions
				result, response, operationErr = testService.GetNotificationChannel(&getOptions)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				getNotificationChannelOptions := testService.NewGetNotificationChannelOptions(accountID, channelID)
				getNotificationChannelOptions.SetAccountID(accountID)
				getNotificationChannelOptions.SetChannelID(channelID)
				getNotificationChannelOptions.SetHeaders(headers)
				result, response, operationErr = testService.GetNotificationChannel(getNotificationChannelOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`UpdateNotificationChannel(updateNotificationChannelOptions *UpdateNotificationChannelOptions)`, func() {
		updateNotificationChannelPath := "/v1/{account_id}/notifications/channels/{channel_id}"
		accountID := "exampleString"
		channelID := "exampleString"
		name := "exampleString"
		typeVar := "exampleString"
		endpoint := "exampleString"
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		updateNotificationChannelPath = strings.Replace(updateNotificationChannelPath, "{account_id}", accountID, 1)
		updateNotificationChannelPath = strings.Replace(updateNotificationChannelPath, "{channel_id}", channelID, 1)
		Context(`Successfully - update notification channel`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(updateNotificationChannelPath))
				Expect(req.Method).To(Equal("PUT"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call UpdateNotificationChannel`, func() {
				defer testServer.Close()

				testService, testServiceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.UpdateNotificationChannel(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//pass Invalid/nil values in options
				var updateOption notificationsapiv1.UpdateNotificationChannelOptions
				result, response, operationErr = testService.UpdateNotificationChannel(&updateOption)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//pass required options
				updateNotificationChannelOptions := testService.NewUpdateNotificationChannelOptions(accountID, channelID, name, typeVar, endpoint)
				result, response, operationErr = testService.UpdateNotificationChannel(updateNotificationChannelOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				//Pass all options
				var alertSource []notificationsapiv1.NotificationChannelAlertSourceItem
				source, _ := testService.NewNotificationChannelAlertSourceItem("ATA")
				source.FindingTypes = []string{"iks", "kms"}
				alertSource = append(alertSource, *source)

				var updateOptions notificationsapiv1.UpdateNotificationChannelOptions
				updateOptions.SetAccountID(accountID)
				updateOptions.SetChannelID(channelID)
				updateOptions.SetName(name)
				updateOptions.SetType(typeVar)
				updateOptions.SetEndpoint(endpoint)
				updateOptions.SetDescription("desc")
				updateOptions.SetSeverity([]string{"low"})
				updateOptions.SetEnabled(false)
				updateOptions.SetAlertSource(alertSource)
				updateOptions.SetHeaders(headers)

				result, response, operationErr = testService.UpdateNotificationChannel(&updateOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`TestNotificationChannel(testNotificationChannelOptions *TestNotificationChannelOptions)`, func() {
		testNotificationChannelPath := "/v1/{account_id}/notifications/channels/{channel_id}/test"
		accountID := "exampleString"
		channelID := "exampleString"
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		testNotificationChannelPath = strings.Replace(testNotificationChannelPath, "{account_id}", accountID, 1)
		testNotificationChannelPath = strings.Replace(testNotificationChannelPath, "{channel_id}", channelID, 1)
		Context(`Successfully - test notification channel`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(testNotificationChannelPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call TestNotificationChannel`, func() {
				defer testServer.Close()

				testService, testServiceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.TestNotificationChannel(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//pass Invalid/nil values in options
				var testOption notificationsapiv1.TestNotificationChannelOptions
				result, response, operationErr = testService.TestNotificationChannel(&testOption)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				testNotificationChannelOptions := testService.NewTestNotificationChannelOptions(accountID, channelID)
				testNotificationChannelOptions.SetAccountID(accountID)
				testNotificationChannelOptions.SetChannelID(channelID)
				testNotificationChannelOptions.SetHeaders(headers)
				result, response, operationErr = testService.TestNotificationChannel(testNotificationChannelOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetPublicKey(getPublicKeyOptions *GetPublicKeyOptions)`, func() {
		getPublicKeyPath := "/v1/{account_id}/notifications/public_key"
		accountID := "exampleString"
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		getPublicKeyPath = strings.Replace(getPublicKeyPath, "{account_id}", accountID, 1)
		Context(`Successfully - fetch notifications public key`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getPublicKeyPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{"publicKey": "fake_PublicKey"}`)
			}))
			It(`Succeed to call GetPublicKey`, func() {
				defer testServer.Close()

				testService, testServiceErr := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.GetPublicKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//pass Invalid/nil values in options
				var getKeyOptions notificationsapiv1.GetPublicKeyOptions
				result, response, operationErr = testService.GetPublicKey(&getKeyOptions)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				getPublicKeyOptions := testService.NewGetPublicKeyOptions(accountID)
				getPublicKeyOptions.SetAccountID(accountID)
				getPublicKeyOptions.SetHeaders(headers)
				result, response, operationErr = testService.GetPublicKey(getPublicKeyOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe("Model constructor tests", func() {
		Context("with a sample service", func() {
			testService, _ := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
				URL:           "http://notificationsapiv1modelgenerator.com",
				Authenticator: &core.NoAuthAuthenticator{},
			})
			It("should call NewNotificationChannelAlertSourceItem successfully", func() {
				providerName := "exampleString"
				model, err := testService.NewNotificationChannelAlertSourceItem(providerName)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
		})
	})
})
