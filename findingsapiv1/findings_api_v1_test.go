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

package findingsapiv1_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v3/core"
	"github.com/go-openapi/strfmt"
	"github.com/ibm-cloud-security/security-advisor-sdk-go/v3/findingsapiv1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe(`FindingsApiV1`, func() {
	Describe(`PostGraph(postGraphOptions *PostGraphOptions)`, func() {
		postGraphPath := "/v1/{account_id}/graph"
		accountID := "exampleString"
		postGraphPath = strings.Replace(postGraphPath, "{account_id}", accountID, 1)
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - query findings`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(postGraphPath))
				Expect(req.Method).To(Equal("POST"))
				res.WriteHeader(200)
			}))
			It(`Succeed to call PostGraph`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				_, operationErr := testService.PostGraph(nil)
				Expect(operationErr).NotTo(BeNil())

				//Pass invalid options
				var options findingsapiv1.PostGraphOptions
				_, operationErr = testService.PostGraph(&options)
				Expect(operationErr).NotTo(BeNil())

				//Pass valid options
				postGraphOptions := testService.NewPostGraphOptions(accountID)
				postGraphOptions.SetBody(ioutil.NopCloser(bytes.NewReader([]byte("foo"))))
				postGraphOptions.SetAccountID(accountID)
				postGraphOptions.SetHeaders(headers)
				postGraphOptions.SetContentType("test")
				response, operationErr := testService.PostGraph(postGraphOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
		})
	})
	Describe(`CreateNote(createNoteOptions *CreateNoteOptions)`, func() {
		createNotePath := "/v1/{account_id}/providers/{provider_id}/notes"
		accountID := "exampleString"
		providerID := "exampleString"
		shortDescription := "exampleString"
		longDescription := "exampleString"
		kind := "CARD"
		id := "exampleString"
		reportedBy := &findingsapiv1.Reporter{ID: core.StringPtr("exampleString"), Title: core.StringPtr("exampleString")}
		createNotePath = strings.Replace(createNotePath, "{account_id}", accountID, 1)
		createNotePath = strings.Replace(createNotePath, "{provider_id}", providerID, 1)
		label := "label"
		url := "https://ss.ss"
		relatedUrl := []findingsapiv1.ApiNoteRelatedURL{{Label: &label, URL: &url}}
		headers := make(map[string]string)
		time := strfmt.DateTime(time.Now())
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Creates a new Note`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(createNotePath))
				Expect(req.Method).To(Equal("POST"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{"short_description": "fake_ShortDescription", "long_description": "fake_LongDescription", "kind": "CARD", "id": "fake_ID", "reported_by": {"id": "fake_ID", "title": "fake_Title"}}`)
			}))
			It(`Succeed to call CreateNote`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.CreateNote(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//Pass invalid options
				var options findingsapiv1.CreateNoteOptions
				result, response, operationErr = testService.CreateNote(&options)

				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//Pass valid options
				createNoteOptions := testService.NewCreateNoteOptions(accountID, providerID, shortDescription, longDescription, kind, id, reportedBy)
				sev := "LOW"
				finding, _ := testService.NewFindingType(&sev)
				reporter, _ := testService.NewReporter("exampleString", "exampleString")
				kpi, _ := testService.NewKpiType("SUM")
				section, _ := testService.NewSection("test", "test")
				card, _ := testService.NewCard("exampleString", "exampleString", "exampleString", []string{"exampleString"}, []findingsapiv1.CardElement{{Kind: core.StringPtr("exampleString"), Text: core.StringPtr("exampleString")}})
				createNoteOptions.SetKpi(kpi)
				createNoteOptions.SetCard(card)
				createNoteOptions.SetSection(section)
				createNoteOptions.SetAccountID(accountID)
				createNoteOptions.SetProviderID(providerID)
				createNoteOptions.SetShortDescription(shortDescription)
				createNoteOptions.SetLongDescription(longDescription)
				createNoteOptions.SetID(id)
				createNoteOptions.SetReportedBy(reporter)
				createNoteOptions.SetKind(core.StringPtr("FINDING"))
				createNoteOptions.SetRelatedURL(relatedUrl)
				createNoteOptions.SetExpirationTime(&time)
				createNoteOptions.SetCreateTime(&time)
				createNoteOptions.SetUpdateTime(&time)
				createNoteOptions.SetShared(false)
				createNoteOptions.SetFinding(finding)
				createNoteOptions.SetHeaders(headers)
				result, response, operationErr = testService.CreateNote(createNoteOptions)
				if operationErr != nil {
					fmt.Println(operationErr)
				}
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`ListNotes(listNotesOptions *ListNotesOptions)`, func() {
		listNotesPath := "/v1/{account_id}/providers/{provider_id}/notes"
		accountID := "exampleString"
		providerID := "exampleString"
		listNotesPath = strings.Replace(listNotesPath, "{account_id}", accountID, 1)
		listNotesPath = strings.Replace(listNotesPath, "{provider_id}", providerID, 1)
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Lists all Notes for a given provider`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(listNotesPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call ListNotes`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.ListNotes(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.ListNotesOptions
				result, response, operationErr = testService.ListNotes(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				//Pass valid
				listNotesOptions := testService.NewListNotesOptions(accountID, providerID)
				listNotesOptions.SetAccountID(accountID)
				listNotesOptions.SetProviderID(providerID)
				listNotesOptions.SetPageSize(10)
				listNotesOptions.SetPageToken("test")
				listNotesOptions.SetHeaders(headers)
				result, response, operationErr = testService.ListNotes(listNotesOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetNote(getNoteOptions *GetNoteOptions)`, func() {
		getNotePath := "/v1/{account_id}/providers/{provider_id}/notes/{note_id}"
		accountID := "exampleString"
		providerID := "exampleString"
		noteID := "exampleString"
		getNotePath = strings.Replace(getNotePath, "{account_id}", accountID, 1)
		getNotePath = strings.Replace(getNotePath, "{provider_id}", providerID, 1)
		getNotePath = strings.Replace(getNotePath, "{note_id}", noteID, 1)
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Returns the requested Note`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getNotePath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{"short_description": "fake_ShortDescription", "long_description": "fake_LongDescription", "kind": "CARD", "id": "fake_ID", "reported_by": {"id": "fake_ID", "title": "fake_Title"}}`)
			}))
			It(`Succeed to call GetNote`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.GetNote(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.GetNoteOptions
				result, response, operationErr = testService.GetNote(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass valid options
				getNoteOptions := testService.NewGetNoteOptions(accountID, providerID, noteID)
				getNoteOptions.SetAccountID(accountID)
				getNoteOptions.SetProviderID(providerID)
				getNoteOptions.SetNoteID(noteID)
				getNoteOptions.SetHeaders(headers)
				result, response, operationErr = testService.GetNote(getNoteOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`UpdateNote(updateNoteOptions *UpdateNoteOptions)`, func() {
		updateNotePath := "/v1/{account_id}/providers/{provider_id}/notes/{note_id}"
		accountID := "exampleString"
		providerID := "exampleString"
		noteID := "exampleString"
		shortDescription := "exampleString"
		longDescription := "exampleString"
		kind := "CARD"
		id := "exampleString"
		reportedBy := &findingsapiv1.Reporter{ID: core.StringPtr("exampleString"), Title: core.StringPtr("exampleString")}
		updateNotePath = strings.Replace(updateNotePath, "{account_id}", accountID, 1)
		updateNotePath = strings.Replace(updateNotePath, "{provider_id}", providerID, 1)
		updateNotePath = strings.Replace(updateNotePath, "{note_id}", noteID, 1)
		time := strfmt.DateTime(time.Now())
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		label := "label"
		url := "https://ss.ss"
		relatedUrl := []findingsapiv1.ApiNoteRelatedURL{{Label: &label, URL: &url}}
		Context(`Successfully - Updates an existing Note`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(updateNotePath))
				Expect(req.Method).To(Equal("PUT"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{"short_description": "fake_ShortDescription", "long_description": "fake_LongDescription", "kind": "CARD", "id": "fake_ID", "reported_by": {"id": "fake_ID", "title": "fake_Title"}}`)
			}))
			It(`Succeed to call UpdateNote`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.UpdateNote(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.UpdateNoteOptions
				result, response, operationErr = testService.UpdateNote(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass valid options
				updateNoteOptions := testService.NewUpdateNoteOptions(accountID, providerID, noteID, shortDescription, longDescription, kind, id, reportedBy)
				sev := "LOW"
				finding, _ := testService.NewFindingType(&sev)
				reporter, _ := testService.NewReporter("exampleString", "exampleString")
				kpi, _ := testService.NewKpiType("SUM")
				section, _ := testService.NewSection("test", "test")
				card, _ := testService.NewCard("exampleString", "exampleString", "exampleString", []string{"exampleString"}, []findingsapiv1.CardElement{{Kind: core.StringPtr("exampleString"), Text: core.StringPtr("exampleString")}})
				updateNoteOptions.SetKpi(kpi)
				updateNoteOptions.SetNoteID("note")
				updateNoteOptions.SetCard(card)
				updateNoteOptions.SetSection(section)
				updateNoteOptions.SetAccountID(accountID)
				updateNoteOptions.SetProviderID(providerID)
				updateNoteOptions.SetShortDescription(shortDescription)
				updateNoteOptions.SetLongDescription(longDescription)
				updateNoteOptions.SetID(id)
				updateNoteOptions.SetReportedBy(reporter)
				updateNoteOptions.SetKind("FINDING")
				updateNoteOptions.SetRelatedURL(relatedUrl)
				updateNoteOptions.SetExpirationTime(&time)
				updateNoteOptions.SetCreateTime(&time)
				updateNoteOptions.SetUpdateTime(&time)
				updateNoteOptions.SetShared(false)
				updateNoteOptions.SetFinding(finding)
				updateNoteOptions.SetHeaders(headers)
				result, response, operationErr = testService.UpdateNote(updateNoteOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`DeleteNote(deleteNoteOptions *DeleteNoteOptions)`, func() {
		deleteNotePath := "/v1/{account_id}/providers/{provider_id}/notes/{note_id}"
		accountID := "exampleString"
		providerID := "exampleString"
		noteID := "exampleString"
		deleteNotePath = strings.Replace(deleteNotePath, "{account_id}", accountID, 1)
		deleteNotePath = strings.Replace(deleteNotePath, "{provider_id}", providerID, 1)
		deleteNotePath = strings.Replace(deleteNotePath, "{note_id}", noteID, 1)
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Deletes the given Note from the system`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(deleteNotePath))
				Expect(req.Method).To(Equal("DELETE"))
				res.WriteHeader(200)
			}))
			It(`Succeed to call DeleteNote`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				response, operationErr := testService.DeleteNote(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.DeleteNoteOptions
				response, operationErr = testService.DeleteNote(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				//Pass valid options
				deleteNoteOptions := testService.NewDeleteNoteOptions(accountID, providerID, noteID)
				deleteNoteOptions.SetAccountID(accountID)
				deleteNoteOptions.SetProviderID(providerID)
				deleteNoteOptions.SetNoteID(noteID)
				deleteNoteOptions.SetHeaders(headers)
				response, operationErr = testService.DeleteNote(deleteNoteOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
		})
	})
	Describe(`GetOccurrenceNote(getOccurrenceNoteOptions *GetOccurrenceNoteOptions)`, func() {
		getOccurrenceNotePath := "/v1/{account_id}/providers/{provider_id}/occurrences/{occurrence_id}/note"
		accountID := "exampleString"
		providerID := "exampleString"
		occurrenceID := "exampleString"
		getOccurrenceNotePath = strings.Replace(getOccurrenceNotePath, "{account_id}", accountID, 1)
		getOccurrenceNotePath = strings.Replace(getOccurrenceNotePath, "{provider_id}", providerID, 1)
		getOccurrenceNotePath = strings.Replace(getOccurrenceNotePath, "{occurrence_id}", occurrenceID, 1)
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Gets the Note attached to the given Occurrence`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getOccurrenceNotePath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{"short_description": "fake_ShortDescription", "long_description": "fake_LongDescription", "kind": "CARD", "id": "fake_ID", "reported_by": {"id": "fake_ID", "title": "fake_Title"}}`)
			}))
			It(`Succeed to call GetOccurrenceNote`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.GetOccurrenceNote(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.GetOccurrenceNoteOptions
				result, response, operationErr = testService.GetOccurrenceNote(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass valid options
				getOccurrenceNoteOptions := testService.NewGetOccurrenceNoteOptions(accountID, providerID, occurrenceID)
				getOccurrenceNoteOptions.SetAccountID(accountID)
				getOccurrenceNoteOptions.SetProviderID(providerID)
				getOccurrenceNoteOptions.SetOccurrenceID(occurrenceID)
				getOccurrenceNoteOptions.SetHeaders(headers)
				result, response, operationErr = testService.GetOccurrenceNote(getOccurrenceNoteOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`CreateOccurrence(createOccurrenceOptions *CreateOccurrenceOptions)`, func() {
		createOccurrencePath := "/v1/{account_id}/providers/{provider_id}/occurrences"
		accountID := "exampleString"
		providerID := "exampleString"
		noteName := "exampleString"
		kind := "CARD"
		id := "exampleString"
		createOccurrencePath = strings.Replace(createOccurrencePath, "{account_id}", accountID, 1)
		createOccurrencePath = strings.Replace(createOccurrencePath, "{provider_id}", providerID, 1)
		time := strfmt.DateTime(time.Now())
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Creates a new Occurrence. Use this method to create Occurrences for a resource`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(createOccurrencePath))
				Expect(req.Method).To(Equal("POST"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{"note_name": "fake_NoteName", "kind": "CARD", "id": "fake_ID"}`)
			}))
			It(`Succeed to call CreateOccurrence`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.CreateOccurrence(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.CreateOccurrenceOptions
				result, response, operationErr = testService.CreateOccurrence(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass valid options
				createOccurrenceOptions := testService.NewCreateOccurrenceOptions(accountID, providerID, noteName, kind, id)
				context := findingsapiv1.Context{ResourceCrn: core.StringPtr("exampleString"), ResourceID: core.StringPtr("exampleString")}
				kpiValue := 3.0
				kpiTotal := 3.0
				kpi := findingsapiv1.Kpi{Value: &kpiValue, Total: &kpiTotal}
				remediationTitle := "title"
				remediationURL := "https://hello.world"
				nextStep := []findingsapiv1.RemediationStep{{Title: &remediationTitle, URL: &remediationURL}}
				severity := "MEDIUM"
				certainity := "LOW"
				finding := findingsapiv1.Finding{Severity: &severity, Certainty: &certainity, NextSteps: nextStep}
				createOccurrenceOptions.SetAccountID(accountID)
				createOccurrenceOptions.SetProviderID(providerID)
				createOccurrenceOptions.SetNoteName(noteName)
				createOccurrenceOptions.SetKind(kind)
				createOccurrenceOptions.SetID(id)
				createOccurrenceOptions.SetResourceURL("https://ss.ss")
				createOccurrenceOptions.SetCreateTime(&time)
				createOccurrenceOptions.SetUpdateTime(&time)
				createOccurrenceOptions.SetContext(&context)
				createOccurrenceOptions.SetRemediation("remediation")
				createOccurrenceOptions.SetFinding(&finding)
				createOccurrenceOptions.SetKpi(&kpi)
				createOccurrenceOptions.SetHeaders(headers)
				createOccurrenceOptions.SetReplaceIfExists(true)
				result, response, operationErr = testService.CreateOccurrence(createOccurrenceOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`ListOccurrences(listOccurrencesOptions *ListOccurrencesOptions)`, func() {
		listOccurrencesPath := "/v1/{account_id}/providers/{provider_id}/occurrences"
		accountID := "exampleString"
		providerID := "exampleString"
		listOccurrencesPath = strings.Replace(listOccurrencesPath, "{account_id}", accountID, 1)
		listOccurrencesPath = strings.Replace(listOccurrencesPath, "{provider_id}", providerID, 1)
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Lists active Occurrences for a given provider matching the filters`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(listOccurrencesPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call ListOccurrences`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.ListOccurrences(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.ListOccurrencesOptions
				result, response, operationErr = testService.ListOccurrences(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(result).To(BeNil())
				Expect(response).To(BeNil())

				// Pass valid options
				listOccurrencesOptions := testService.NewListOccurrencesOptions(accountID, providerID)
				listOccurrencesOptions.SetAccountID(accountID)
				listOccurrencesOptions.SetProviderID(providerID)
				listOccurrencesOptions.SetPageSize(10)
				listOccurrencesOptions.SetPageToken("token")
				listOccurrencesOptions.SetHeaders(headers)
				result, response, operationErr = testService.ListOccurrences(listOccurrencesOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`ListNoteOccurrences(listNoteOccurrencesOptions *ListNoteOccurrencesOptions)`, func() {
		listNoteOccurrencesPath := "/v1/{account_id}/providers/{provider_id}/notes/{note_id}/occurrences"
		accountID := "exampleString"
		providerID := "exampleString"
		noteID := "exampleString"
		listNoteOccurrencesPath = strings.Replace(listNoteOccurrencesPath, "{account_id}", accountID, 1)
		listNoteOccurrencesPath = strings.Replace(listNoteOccurrencesPath, "{provider_id}", providerID, 1)
		listNoteOccurrencesPath = strings.Replace(listNoteOccurrencesPath, "{note_id}", noteID, 1)
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Lists Occurrences referencing the specified Note. Use this method to get all occurrences referencing your Note across all your customer providers`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(listNoteOccurrencesPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call ListNoteOccurrences`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.ListNoteOccurrences(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.ListNoteOccurrencesOptions
				result, response, operationErr = testService.ListNoteOccurrences(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(result).To(BeNil())
				Expect(response).To(BeNil())

				// Pass valid options
				listNoteOccurrencesOptions := testService.NewListNoteOccurrencesOptions(accountID, providerID, noteID)
				listNoteOccurrencesOptions.SetAccountID(accountID)
				listNoteOccurrencesOptions.SetProviderID(providerID)
				listNoteOccurrencesOptions.SetNoteID(noteID)
				listNoteOccurrencesOptions.SetPageSize(10)
				listNoteOccurrencesOptions.SetPageToken("token")
				listNoteOccurrencesOptions.SetHeaders(headers)
				result, response, operationErr = testService.ListNoteOccurrences(listNoteOccurrencesOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`GetOccurrence(getOccurrenceOptions *GetOccurrenceOptions)`, func() {
		getOccurrencePath := "/v1/{account_id}/providers/{provider_id}/occurrences/{occurrence_id}"
		accountID := "exampleString"
		providerID := "exampleString"
		occurrenceID := "exampleString"
		getOccurrencePath = strings.Replace(getOccurrencePath, "{account_id}", accountID, 1)
		getOccurrencePath = strings.Replace(getOccurrencePath, "{provider_id}", providerID, 1)
		getOccurrencePath = strings.Replace(getOccurrencePath, "{occurrence_id}", occurrenceID, 1)
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Returns the requested Occurrence`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(getOccurrencePath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call GetOccurrence`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.GetOccurrence(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.GetOccurrenceOptions
				result, response, operationErr = testService.GetOccurrence(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(result).To(BeNil())
				Expect(response).To(BeNil())

				// Pass valid options
				getOccurrenceOptions := testService.NewGetOccurrenceOptions(accountID, providerID, occurrenceID)
				getOccurrenceOptions.SetAccountID(accountID)
				getOccurrenceOptions.SetProviderID(providerID)
				getOccurrenceOptions.SetOccurrenceID(occurrenceID)
				getOccurrenceOptions.SetHeaders(headers)
				result, response, operationErr = testService.GetOccurrence(getOccurrenceOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`UpdateOccurrence(updateOccurrenceOptions *UpdateOccurrenceOptions)`, func() {
		updateOccurrencePath := "/v1/{account_id}/providers/{provider_id}/occurrences/{occurrence_id}"
		accountID := "exampleString"
		providerID := "exampleString"
		occurrenceID := "exampleString"
		noteName := "exampleString"
		kind := "FINDING_COUNT"
		id := "exampleString"
		updateOccurrencePath = strings.Replace(updateOccurrencePath, "{account_id}", accountID, 1)
		updateOccurrencePath = strings.Replace(updateOccurrencePath, "{provider_id}", providerID, 1)
		updateOccurrencePath = strings.Replace(updateOccurrencePath, "{occurrence_id}", occurrenceID, 1)
		time := strfmt.DateTime(time.Now())
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Updates an existing Occurrence`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(updateOccurrencePath))
				Expect(req.Method).To(Equal("PUT"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{"note_name": "fake_NoteName", "kind": "FINDING_COUNT", "id": "fake_ID"}`)
			}))
			It(`Succeed to call UpdateOccurrence`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.UpdateOccurrence(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.UpdateOccurrenceOptions
				result, response, operationErr = testService.UpdateOccurrence(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(result).To(BeNil())
				Expect(response).To(BeNil())

				// Pass valid options
				updateOccurrenceOptions := testService.NewUpdateOccurrenceOptions(accountID, providerID, occurrenceID, noteName, kind, id)
				context := findingsapiv1.Context{ResourceCrn: core.StringPtr("exampleString"), ResourceID: core.StringPtr("exampleString")}
				kpiValue := 3.0
				kpiTotal := 3.0
				kpi := findingsapiv1.Kpi{Value: &kpiValue, Total: &kpiTotal}
				remediationTitle := "title"
				remediationURL := "https://hello.world"
				nextStep := []findingsapiv1.RemediationStep{{Title: &remediationTitle, URL: &remediationURL}}
				severity := "MEDIUM"
				certainity := "LOW"
				finding := findingsapiv1.Finding{Severity: &severity, Certainty: &certainity, NextSteps: nextStep}
				updateOccurrenceOptions.SetAccountID(accountID)
				updateOccurrenceOptions.SetProviderID(providerID)
				updateOccurrenceOptions.SetNoteName(noteName)
				updateOccurrenceOptions.SetKind(kind)
				updateOccurrenceOptions.SetID(id)
				updateOccurrenceOptions.SetResourceURL("https://ss.ss")
				updateOccurrenceOptions.SetCreateTime(&time)
				updateOccurrenceOptions.SetUpdateTime(&time)
				updateOccurrenceOptions.SetContext(&context)
				updateOccurrenceOptions.SetRemediation("remediation")
				updateOccurrenceOptions.SetFinding(&finding)
				updateOccurrenceOptions.SetKpi(&kpi)
				updateOccurrenceOptions.SetHeaders(headers)
				result, response, operationErr = testService.UpdateOccurrence(updateOccurrenceOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe(`DeleteOccurrence(deleteOccurrenceOptions *DeleteOccurrenceOptions)`, func() {
		deleteOccurrencePath := "/v1/{account_id}/providers/{provider_id}/occurrences/{occurrence_id}"
		accountID := "exampleString"
		providerID := "exampleString"
		occurrenceID := "exampleString"
		deleteOccurrencePath = strings.Replace(deleteOccurrencePath, "{account_id}", accountID, 1)
		deleteOccurrencePath = strings.Replace(deleteOccurrencePath, "{provider_id}", providerID, 1)
		deleteOccurrencePath = strings.Replace(deleteOccurrencePath, "{occurrence_id}", occurrenceID, 1)
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Deletes the given Occurrence from the system`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(deleteOccurrencePath))
				Expect(req.Method).To(Equal("DELETE"))
				res.WriteHeader(200)
			}))
			It(`Succeed to call DeleteOccurrence`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				response, operationErr := testService.DeleteOccurrence(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.DeleteOccurrenceOptions
				response, operationErr = testService.DeleteOccurrence(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Pass valid options
				deleteOccurrenceOptions := testService.NewDeleteOccurrenceOptions(accountID, providerID, occurrenceID)
				deleteOccurrenceOptions.SetAccountID(accountID)
				deleteOccurrenceOptions.SetProviderID(providerID)
				deleteOccurrenceOptions.SetOccurrenceID(occurrenceID)
				deleteOccurrenceOptions.SetHeaders(headers)
				response, operationErr = testService.DeleteOccurrence(deleteOccurrenceOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
		})
	})
	Describe(`ListProviders(listProvidersOptions *ListProvidersOptions)`, func() {
		listProvidersPath := "/v1/{account_id}/providers"
		accountID := "exampleString"
		listProvidersPath = strings.Replace(listProvidersPath, "{account_id}", accountID, 1)
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		Context(`Successfully - Lists all Providers for a given account id`, func() {
			testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
				defer GinkgoRecover()

				// Verify the contents of the request
				Expect(req.URL.Path).To(Equal(listProvidersPath))
				Expect(req.Method).To(Equal("GET"))
				res.Header().Set("Content-type", "application/json")
				res.WriteHeader(200)
				fmt.Fprintf(res, `{}`)
			}))
			It(`Succeed to call ListProviders`, func() {
				defer testServer.Close()

				testService, testServiceErr := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(testServiceErr).To(BeNil())
				Expect(testService).ToNot(BeNil())

				// Pass empty options
				result, response, operationErr := testService.ListProviders(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Pass invalid options
				var options findingsapiv1.ListProvidersOptions
				result, response, operationErr = testService.ListProviders(&options)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				listProvidersOptions := testService.NewListProvidersOptions(accountID)
				listProvidersOptions.SetAccountID(accountID)
				listProvidersOptions.SetLimit(10)
				listProvidersOptions.SetSkip(10)
				listProvidersOptions.SetStartProviderID("start")
				listProvidersOptions.SetEndProviderID("end")
				listProvidersOptions.SetHeaders(headers)
				result, response, operationErr = testService.ListProviders(listProvidersOptions)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())
			})
		})
	})
	Describe("Model constructor tests", func() {
		Context("with a sample service", func() {
			testService, _ := findingsapiv1.NewFindingsApiV1(&findingsapiv1.FindingsApiV1Options{
				URL:           "http://findingsapiv1modelgenerator.com",
				Authenticator: &core.NoAuthAuthenticator{},
			})
			It("should call NewCard successfully", func() {
				section := "exampleString"
				title := "exampleString"
				subtitle := "exampleString"
				findingNoteNames := []string{}
				elements := []findingsapiv1.CardElement{}
				model, err := testService.NewCard(section, title, subtitle, findingNoteNames, elements)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewCardElement successfully", func() {
				kind := "exampleString"
				text := "exampleString"
				model, err := testService.NewCardElement(kind, text)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewFindingCountValueType successfully", func() {
				kind := "exampleString"
				findingNoteNames := []string{}
				text := "exampleString"
				model, err := testService.NewFindingCountValueType(kind, findingNoteNames, text)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewFindingType successfully", func() {
				severity := "LOW"
				model, err := testService.NewFindingType(&severity)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewKpi successfully", func() {
				value := 1234
				model, err := testService.NewKpi(float64(value))
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewKpiType successfully", func() {
				aggregationType := "exampleString"
				model, err := testService.NewKpiType(aggregationType)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewReporter successfully", func() {
				id := "exampleString"
				title := "exampleString"
				model, err := testService.NewReporter(id, title)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewSection successfully", func() {
				title := "exampleString"
				image := "exampleString"
				model, err := testService.NewSection(title, image)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewSocketAddress successfully", func() {
				address := "exampleString"
				model, err := testService.NewSocketAddress(address)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewValueType successfully", func() {
				kind := "exampleString"
				text := "exampleString"
				model, err := testService.NewValueType(kind, text)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewApiNote successfully", func() {
				shortDescription := "exampleString"
				longDescription := "exampleString"
				kind := "CARD"
				id := "exampleString"
				reportedBy := &findingsapiv1.Reporter{ID: core.StringPtr("exampleString"), Title: core.StringPtr("exampleString")}
				model, err := testService.NewApiNote(shortDescription, longDescription, kind, id, reportedBy)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewApiOccurrence successfully", func() {
				noteName := "exampleString"
				kind := "FINDING"
				id := "exampleString"
				model, err := testService.NewApiOccurrence(noteName, kind, id)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewBreakdownCardElement successfully", func() {
				kind := "exampleString"
				text := "exampleString"
				valueTypes := []findingsapiv1.ValueType{}
				model, err := testService.NewBreakdownCardElement(kind, text, valueTypes)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewNumericCardElement successfully", func() {
				kind := "exampleString"
				text := "exampleString"
				valueType := make(map[string]interface{})
				model, err := testService.NewNumericCardElement(kind, text, valueType)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It("should call NewTimeSeriesCardElement successfully", func() {
				kind := "exampleString"
				text := "exampleString"
				valueTypes := []findingsapiv1.FindingCountValueType{}
				model, err := testService.NewTimeSeriesCardElement(kind, text, valueTypes)
				Expect(model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
		})
	})
})
