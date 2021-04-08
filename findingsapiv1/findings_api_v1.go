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

// Package findingsapiv1 : Operations and models for the FindingsApiV1 service
package findingsapiv1

import (
	"fmt"
	"io"

	"github.com/IBM/go-sdk-core/v3/core"
	"github.com/go-openapi/strfmt"
	common "github.com/ibm-cloud-security/security-advisor-sdk-go/common"
)

// FindingsApiV1 : The Findings API
//
// Version: 1.0.0
type FindingsApiV1 struct {
	Service *core.BaseService
}

// DefaultServiceURL is the default URL to make service requests to.
const DefaultServiceURL = "https://us-south.secadvisor.cloud.ibm.com/findings"

// DefaultServiceName is the default key used to find external configuration information.
const DefaultServiceName = "findings_api"

// FindingsApiV1Options : Service options
type FindingsApiV1Options struct {
	ServiceName   string
	URL           string
	Authenticator core.Authenticator
}

// NewFindingsApiV1UsingExternalConfig : constructs an instance of FindingsApiV1 with passed in options and external configuration.
func NewFindingsApiV1UsingExternalConfig(options *FindingsApiV1Options) (findingsApi *FindingsApiV1, err error) {
	if options.ServiceName == "" {
		options.ServiceName = DefaultServiceName
	}

	if options.Authenticator == nil {
		options.Authenticator, err = core.GetAuthenticatorFromEnvironment(options.ServiceName)
		if err != nil {
			return
		}
	}

	findingsApi, err = NewFindingsApiV1(options)
	if err != nil {
		return
	}

	err = findingsApi.Service.ConfigureService(options.ServiceName)
	if err != nil {
		return
	}

	if options.URL != "" {
		err = findingsApi.Service.SetServiceURL(options.URL)
	}
	return
}

// NewFindingsApiV1 : constructs an instance of FindingsApiV1 with passed in options.
func NewFindingsApiV1(options *FindingsApiV1Options) (service *FindingsApiV1, err error) {
	serviceOptions := &core.ServiceOptions{
		URL:           DefaultServiceURL,
		Authenticator: options.Authenticator,
	}

	baseService, err := core.NewBaseService(serviceOptions)
	if err != nil {
		return
	}

	if options.URL != "" {
		err = baseService.SetServiceURL(options.URL)
		if err != nil {
			return
		}
	}

	service = &FindingsApiV1{
		Service: baseService,
	}

	return
}

// SetServiceURL sets the service URL
func (findingsApi *FindingsApiV1) SetServiceURL(url string) error {
	return findingsApi.Service.SetServiceURL(url)
}

// PostGraph : query findings
// query findings.
func (findingsApi *FindingsApiV1) PostGraph(postGraphOptions *PostGraphOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(postGraphOptions, "postGraphOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(postGraphOptions, "postGraphOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "graph"}
	pathParameters := []string{*postGraphOptions.AccountID}

	builder := core.NewRequestBuilder(core.POST)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range postGraphOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "PostGraph")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	if postGraphOptions.ContentType != nil {
		builder.AddHeader("Content-Type", fmt.Sprint(*postGraphOptions.ContentType))
	}
	_, err = builder.SetBodyContent(core.StringNilMapper(postGraphOptions.ContentType), nil, nil, postGraphOptions.Body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, "{}")

	return
}

// CreateNote : Creates a new `Note`
func (findingsApi *FindingsApiV1) CreateNote(createNoteOptions *CreateNoteOptions) (result *ApiNote, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(createNoteOptions, "createNoteOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(createNoteOptions, "createNoteOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "notes"}
	pathParameters := []string{*createNoteOptions.AccountID, *createNoteOptions.ProviderID}

	builder := core.NewRequestBuilder(core.POST)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range createNoteOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "CreateNote")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if createNoteOptions.ShortDescription != nil {
		body["short_description"] = createNoteOptions.ShortDescription
	}
	if createNoteOptions.LongDescription != nil {
		body["long_description"] = createNoteOptions.LongDescription
	}
	if createNoteOptions.Kind != nil {
		body["kind"] = createNoteOptions.Kind
	}
	if createNoteOptions.ID != nil {
		body["id"] = createNoteOptions.ID
	}
	if createNoteOptions.ReportedBy != nil {
		body["reported_by"] = createNoteOptions.ReportedBy
	}
	if createNoteOptions.RelatedURL != nil {
		body["related_url"] = createNoteOptions.RelatedURL
	}
	if createNoteOptions.ExpirationTime != nil {
		body["expiration_time"] = createNoteOptions.ExpirationTime
	}
	if createNoteOptions.CreateTime != nil {
		body["create_time"] = createNoteOptions.CreateTime
	}
	if createNoteOptions.UpdateTime != nil {
		body["update_time"] = createNoteOptions.UpdateTime
	}
	if createNoteOptions.Shared != nil {
		body["shared"] = createNoteOptions.Shared
	}
	if createNoteOptions.Finding != nil {
		body["finding"] = createNoteOptions.Finding
	}
	if createNoteOptions.Kpi != nil {
		body["kpi"] = createNoteOptions.Kpi
	}
	if createNoteOptions.Card != nil {
		body["card"] = createNoteOptions.Card
	}
	if createNoteOptions.Section != nil {
		body["section"] = createNoteOptions.Section
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiNote))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiNote)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response")
		}
	}

	return
}

// ListNotes : Lists all `Notes` for a given provider
func (findingsApi *FindingsApiV1) ListNotes(listNotesOptions *ListNotesOptions) (result *ApiListNotesResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(listNotesOptions, "listNotesOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(listNotesOptions, "listNotesOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "notes"}
	pathParameters := []string{*listNotesOptions.AccountID, *listNotesOptions.ProviderID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range listNotesOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "ListNotes")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	if listNotesOptions.PageSize != nil {
		builder.AddQuery("page_size", fmt.Sprint(*listNotesOptions.PageSize))
	}
	if listNotesOptions.PageToken != nil {
		builder.AddQuery("page_token", fmt.Sprint(*listNotesOptions.PageToken))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiListNotesResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiListNotesResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// GetNote : Returns the requested `Note`
func (findingsApi *FindingsApiV1) GetNote(getNoteOptions *GetNoteOptions) (result *ApiNote, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getNoteOptions, "getNoteOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getNoteOptions, "getNoteOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "notes"}
	pathParameters := []string{*getNoteOptions.AccountID, *getNoteOptions.ProviderID, *getNoteOptions.NoteID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range getNoteOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "GetNote")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiNote))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiNote)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response")
		}
	}

	return
}

// UpdateNote : Updates an existing `Note`
func (findingsApi *FindingsApiV1) UpdateNote(updateNoteOptions *UpdateNoteOptions) (result *ApiNote, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(updateNoteOptions, "updateNoteOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(updateNoteOptions, "updateNoteOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "notes"}
	pathParameters := []string{*updateNoteOptions.AccountID, *updateNoteOptions.ProviderID, *updateNoteOptions.ID}

	builder := core.NewRequestBuilder(core.PUT)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range updateNoteOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "UpdateNote")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if updateNoteOptions.ShortDescription != nil {
		body["short_description"] = updateNoteOptions.ShortDescription
	}
	if updateNoteOptions.LongDescription != nil {
		body["long_description"] = updateNoteOptions.LongDescription
	}
	if updateNoteOptions.Kind != nil {
		body["kind"] = updateNoteOptions.Kind
	}
	if updateNoteOptions.ID != nil {
		body["id"] = updateNoteOptions.ID
	}
	if updateNoteOptions.ReportedBy != nil {
		body["reported_by"] = updateNoteOptions.ReportedBy
	}
	if updateNoteOptions.RelatedURL != nil {
		body["related_url"] = updateNoteOptions.RelatedURL
	}
	if updateNoteOptions.ExpirationTime != nil {
		body["expiration_time"] = updateNoteOptions.ExpirationTime
	}
	if updateNoteOptions.CreateTime != nil {
		body["create_time"] = updateNoteOptions.CreateTime
	}
	if updateNoteOptions.UpdateTime != nil {
		body["update_time"] = updateNoteOptions.UpdateTime
	}
	if updateNoteOptions.Shared != nil {
		body["shared"] = updateNoteOptions.Shared
	}
	if updateNoteOptions.Finding != nil {
		body["finding"] = updateNoteOptions.Finding
	}
	if updateNoteOptions.Kpi != nil {
		body["kpi"] = updateNoteOptions.Kpi
	}
	if updateNoteOptions.Card != nil {
		body["card"] = updateNoteOptions.Card
	}
	if updateNoteOptions.Section != nil {
		body["section"] = updateNoteOptions.Section
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiNote))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiNote)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response")
		}
	}

	return
}

// DeleteNote : Deletes the given `Note` from the system
func (findingsApi *FindingsApiV1) DeleteNote(deleteNoteOptions *DeleteNoteOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(deleteNoteOptions, "deleteNoteOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(deleteNoteOptions, "deleteNoteOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "notes"}
	pathParameters := []string{*deleteNoteOptions.AccountID, *deleteNoteOptions.ProviderID, *deleteNoteOptions.NoteID}

	builder := core.NewRequestBuilder(core.DELETE)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range deleteNoteOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "DeleteNote")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, nil)

	return
}

// GetOccurrenceNote : Gets the `Note` attached to the given `Occurrence`
func (findingsApi *FindingsApiV1) GetOccurrenceNote(getOccurrenceNoteOptions *GetOccurrenceNoteOptions) (result *ApiNote, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getOccurrenceNoteOptions, "getOccurrenceNoteOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getOccurrenceNoteOptions, "getOccurrenceNoteOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "occurrences", "note"}
	pathParameters := []string{*getOccurrenceNoteOptions.AccountID, *getOccurrenceNoteOptions.ProviderID, *getOccurrenceNoteOptions.OccurrenceID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range getOccurrenceNoteOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "GetOccurrenceNote")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiNote))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiNote)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// CreateOccurrence : Creates a new `Occurrence`. Use this method to create `Occurrences` for a resource
func (findingsApi *FindingsApiV1) CreateOccurrence(createOccurrenceOptions *CreateOccurrenceOptions) (result *ApiOccurrence, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(createOccurrenceOptions, "createOccurrenceOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(createOccurrenceOptions, "createOccurrenceOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "occurrences"}
	pathParameters := []string{*createOccurrenceOptions.AccountID, *createOccurrenceOptions.ProviderID}

	builder := core.NewRequestBuilder(core.POST)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range createOccurrenceOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "CreateOccurrence")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")
	if createOccurrenceOptions.ReplaceIfExists != nil {
		builder.AddHeader("Replace-If-Exists", fmt.Sprint(*createOccurrenceOptions.ReplaceIfExists))
	}

	body := make(map[string]interface{})
	if createOccurrenceOptions.NoteName != nil {
		body["note_name"] = createOccurrenceOptions.NoteName
	}
	if createOccurrenceOptions.Kind != nil {
		body["kind"] = createOccurrenceOptions.Kind
	}
	if createOccurrenceOptions.ID != nil {
		body["id"] = createOccurrenceOptions.ID
	}
	if createOccurrenceOptions.ResourceURL != nil {
		body["resource_url"] = createOccurrenceOptions.ResourceURL
	}
	if createOccurrenceOptions.Remediation != nil {
		body["remediation"] = createOccurrenceOptions.Remediation
	}
	if createOccurrenceOptions.CreateTime != nil {
		body["create_time"] = createOccurrenceOptions.CreateTime
	}
	if createOccurrenceOptions.UpdateTime != nil {
		body["update_time"] = createOccurrenceOptions.UpdateTime
	}
	if createOccurrenceOptions.Context != nil {
		body["context"] = createOccurrenceOptions.Context
	}
	if createOccurrenceOptions.Finding != nil {
		body["finding"] = createOccurrenceOptions.Finding
	}
	if createOccurrenceOptions.Kpi != nil {
		body["kpi"] = createOccurrenceOptions.Kpi
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiOccurrence))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiOccurrence)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response")
		}
	}

	return
}

// ListOccurrences : Lists active `Occurrences` for a given provider matching the filters
func (findingsApi *FindingsApiV1) ListOccurrences(listOccurrencesOptions *ListOccurrencesOptions) (result *ApiListOccurrencesResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(listOccurrencesOptions, "listOccurrencesOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(listOccurrencesOptions, "listOccurrencesOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "occurrences"}
	pathParameters := []string{*listOccurrencesOptions.AccountID, *listOccurrencesOptions.ProviderID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range listOccurrencesOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "ListOccurrences")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	if listOccurrencesOptions.PageSize != nil {
		builder.AddQuery("page_size", fmt.Sprint(*listOccurrencesOptions.PageSize))
	}
	if listOccurrencesOptions.PageToken != nil {
		builder.AddQuery("page_token", fmt.Sprint(*listOccurrencesOptions.PageToken))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiListOccurrencesResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiListOccurrencesResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// ListNoteOccurrences : Lists `Occurrences` referencing the specified `Note`. Use this method to get all occurrences referencing your `Note` across all your customer providers
func (findingsApi *FindingsApiV1) ListNoteOccurrences(listNoteOccurrencesOptions *ListNoteOccurrencesOptions) (result *ApiListNoteOccurrencesResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(listNoteOccurrencesOptions, "listNoteOccurrencesOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(listNoteOccurrencesOptions, "listNoteOccurrencesOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "notes", "occurrences"}
	pathParameters := []string{*listNoteOccurrencesOptions.AccountID, *listNoteOccurrencesOptions.ProviderID, *listNoteOccurrencesOptions.NoteID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range listNoteOccurrencesOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "ListNoteOccurrences")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	if listNoteOccurrencesOptions.PageSize != nil {
		builder.AddQuery("page_size", fmt.Sprint(*listNoteOccurrencesOptions.PageSize))
	}
	if listNoteOccurrencesOptions.PageToken != nil {
		builder.AddQuery("page_token", fmt.Sprint(*listNoteOccurrencesOptions.PageToken))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiListNoteOccurrencesResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiListNoteOccurrencesResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// GetOccurrence : Returns the requested `Occurrence`
func (findingsApi *FindingsApiV1) GetOccurrence(getOccurrenceOptions *GetOccurrenceOptions) (result *ApiOccurrence, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getOccurrenceOptions, "getOccurrenceOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getOccurrenceOptions, "getOccurrenceOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "occurrences"}
	pathParameters := []string{*getOccurrenceOptions.AccountID, *getOccurrenceOptions.ProviderID, *getOccurrenceOptions.OccurrenceID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range getOccurrenceOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "GetOccurrence")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiOccurrence))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiOccurrence)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response")
		}
	}

	return
}

// UpdateOccurrence : Updates an existing `Occurrence`
func (findingsApi *FindingsApiV1) UpdateOccurrence(updateOccurrenceOptions *UpdateOccurrenceOptions) (result *ApiOccurrence, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(updateOccurrenceOptions, "updateOccurrenceOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(updateOccurrenceOptions, "updateOccurrenceOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "occurrences"}
	pathParameters := []string{*updateOccurrenceOptions.AccountID, *updateOccurrenceOptions.ProviderID, *updateOccurrenceOptions.ID}

	builder := core.NewRequestBuilder(core.PUT)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range updateOccurrenceOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "UpdateOccurrence")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if updateOccurrenceOptions.NoteName != nil {
		body["note_name"] = updateOccurrenceOptions.NoteName
	}
	if updateOccurrenceOptions.Kind != nil {
		body["kind"] = updateOccurrenceOptions.Kind
	}
	if updateOccurrenceOptions.ID != nil {
		body["id"] = updateOccurrenceOptions.ID
	}
	if updateOccurrenceOptions.ResourceURL != nil {
		body["resource_url"] = updateOccurrenceOptions.ResourceURL
	}
	if updateOccurrenceOptions.Remediation != nil {
		body["remediation"] = updateOccurrenceOptions.Remediation
	}
	if updateOccurrenceOptions.CreateTime != nil {
		body["create_time"] = updateOccurrenceOptions.CreateTime
	}
	if updateOccurrenceOptions.UpdateTime != nil {
		body["update_time"] = updateOccurrenceOptions.UpdateTime
	}
	if updateOccurrenceOptions.Context != nil {
		body["context"] = updateOccurrenceOptions.Context
	}
	if updateOccurrenceOptions.Finding != nil {
		body["finding"] = updateOccurrenceOptions.Finding
	}
	if updateOccurrenceOptions.Kpi != nil {
		body["kpi"] = updateOccurrenceOptions.Kpi
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiOccurrence))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiOccurrence)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response")
		}
	}

	return
}

// DeleteOccurrence : Deletes the given `Occurrence` from the system
func (findingsApi *FindingsApiV1) DeleteOccurrence(deleteOccurrenceOptions *DeleteOccurrenceOptions) (response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(deleteOccurrenceOptions, "deleteOccurrenceOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(deleteOccurrenceOptions, "deleteOccurrenceOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers", "occurrences"}
	pathParameters := []string{*deleteOccurrenceOptions.AccountID, *deleteOccurrenceOptions.ProviderID, *deleteOccurrenceOptions.OccurrenceID}

	builder := core.NewRequestBuilder(core.DELETE)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range deleteOccurrenceOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "DeleteOccurrence")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, nil)

	return
}

// ListProviders : Lists all `Providers` for a given account id
func (findingsApi *FindingsApiV1) ListProviders(listProvidersOptions *ListProvidersOptions) (result *ApiListProvidersResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(listProvidersOptions, "listProvidersOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(listProvidersOptions, "listProvidersOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "providers"}
	pathParameters := []string{*listProvidersOptions.AccountID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(findingsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range listProvidersOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("findings_api", "V1", "ListProviders")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	if listProvidersOptions.Limit != nil {
		builder.AddQuery("limit", fmt.Sprint(*listProvidersOptions.Limit))
	}
	if listProvidersOptions.Skip != nil {
		builder.AddQuery("skip", fmt.Sprint(*listProvidersOptions.Skip))
	}
	if listProvidersOptions.StartProviderID != nil {
		builder.AddQuery("start_provider_id", fmt.Sprint(*listProvidersOptions.StartProviderID))
	}
	if listProvidersOptions.EndProviderID != nil {
		builder.AddQuery("end_provider_id", fmt.Sprint(*listProvidersOptions.EndProviderID))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = findingsApi.Service.Request(request, new(ApiListProvidersResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ApiListProvidersResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// Card : Card provides details about a card kind of note.
type Card struct {

	// The section this card belongs to.
	Section *string `json:"section" validate:"required"`

	// The title of this card.
	Title *string `json:"title" validate:"required"`

	// The subtitle of this card.
	Subtitle *string `json:"subtitle" validate:"required"`

	// The order of the card in which it will appear on SA dashboard in the mentioned section.
	Order *int64 `json:"order,omitempty"`

	// The finding note names associated to this card.
	FindingNoteNames []string `json:"finding_note_names" validate:"required"`

	RequiresConfiguration *bool `json:"requires_configuration,omitempty"`

	// The text associated to the card's badge.
	BadgeText *string `json:"badge_text,omitempty"`

	// The base64 content of the image associated to the card's badge.
	BadgeImage *string `json:"badge_image,omitempty"`

	// The elements of this card.
	Elements []CardElement `json:"elements" validate:"required"`
}

// NewCard : Instantiate Card (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewCard(section string, title string, subtitle string, findingNoteNames []string, elements []CardElement) (model *Card, err error) {
	model = &Card{
		Section:          core.StringPtr(section),
		Title:            core.StringPtr(title),
		Subtitle:         core.StringPtr(subtitle),
		FindingNoteNames: findingNoteNames,
		Elements:         elements,
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

//CardValueType or types associated to this card element
type CardValueType struct {
	//Kind of the value
	// - KPI: Kind of value derived from a KPI occurrence
	// - FINDING_COUNT: Kind of value derived from a count of finding occurrences
	Kind *string `json:"kind" validate:"required"`

	// the names of the finding note associated that act as filters for counting the occurrences.
	//Required for values of kind "FINDING_COUNT"
	FindingNoteNames []string `json:"finding_note_names,omitempty"`

	// The name of the kpi note associated to the occurrence with the value for this card element value type
	//Required for only for values of kind "KPI"
	KpiNoteName *string `json:"kpi_note_name,omitempty"`

	//Text of the element. Required for kind "BREAKDOWN", "TIMESERIES"
	Text *string `json:"text,omitempty"`
}

// CardElement : CardElement provides details about the elements of a Card.
type CardElement struct {

	// Kind of element
	// - NUMERIC&#58; Single numeric value
	// - BREAKDOWN&#58; Breakdown of numeric values
	// - TIME_SERIES&#58; Time-series of numeric values.
	Kind *string `json:"kind" validate:"required"`

	//Text to display on the card
	Text *string `json:"text" validate:"required"`

	//ValueType the type of an element in a card
	ValueType *CardValueType `json:"value_type,omitempty"`

	//ValueTypes the type of an element in a card
	ValueTypes []CardValueType `json:"value_types,omitempty"`

	// The default time range of this card element.
	DefaultTimeRange *string `json:"default_time_range,omitempty"`

	// The default interval of the time series.
	DefaultInterval *string `json:"default_interval,omitempty"`
}

// Constants associated with the CardElement.Kind property.
// Kind of element
// - NUMERIC&#58; Single numeric value
// - BREAKDOWN&#58; Breakdown of numeric values
// - TIME_SERIES&#58; Time-series of numeric values.
const (
	CardElement_Kind_Breakdown  = "BREAKDOWN"
	CardElement_Kind_Numeric    = "NUMERIC"
	CardElement_Kind_TimeSeries = "TIME_SERIES"
)

// NewCardElement : Instantiate CardElement (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewCardElement(kind string, text string) (model *CardElement, err error) {
	model = &CardElement{
		Kind: core.StringPtr(kind),
		Text: core.StringPtr(text),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// Certainty : Note provider-assigned confidence on the validity of an occurrence
// - LOW&#58; Low Certainty
// - MEDIUM&#58; Medium Certainty
// - HIGH&#58; High Certainty.
type Certainty struct {
}

// Context : Context struct
type Context struct {

	// The IBM Cloud region.
	Region *string `json:"region,omitempty"`

	// The resource CRN (e.g. certificate CRN, image CRN).
	ResourceCrn *string `json:"resource_crn,omitempty"`

	// The resource ID, in case the CRN is not available.
	ResourceID *string `json:"resource_id,omitempty"`

	// The user-friendly resource name.
	ResourceName *string `json:"resource_name,omitempty"`

	// The resource type name (e.g. Pod, Cluster, Certificate, Image).
	ResourceType *string `json:"resource_type,omitempty"`

	// The service CRN (e.g. CertMgr Instance CRN).
	ServiceCrn *string `json:"service_crn,omitempty"`

	// The service name (e.g. CertMgr).
	ServiceName *string `json:"service_name,omitempty"`

	// The name of the environment the occurrence applies to.
	EnvironmentName *string `json:"environment_name,omitempty"`

	// The name of the component the occurrence applies to.
	ComponentName *string `json:"component_name,omitempty"`

	// The id of the toolchain the occurrence applies to.
	ToolchainID *string `json:"toolchain_id,omitempty"`
}

// CreateNoteOptions : The CreateNote options.
type CreateNoteOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Part of `parent`. This field contains the provider_id for example: providers/{provider_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// A one sentence description of this `Note`.
	ShortDescription *string `json:"short_description" validate:"required"`

	// A detailed description of this `Note`.
	LongDescription *string `json:"long_description" validate:"required"`

	// Output only. This explicitly denotes which kind of note is specified. This
	// field can be used as a filter in list requests.
	Kind *string `json:"kind" validate:"required"`

	ID *string `json:"id" validate:"required"`

	// Details about the reporter of this `Note`.
	ReportedBy *Reporter `json:"reported_by" validate:"required"`

	RelatedURL []ApiNoteRelatedURL `json:"related_url,omitempty"`

	// Time of expiration for this note, null if note does not expire.
	ExpirationTime *strfmt.DateTime `json:"expiration_time,omitempty"`

	// Output only. The time this note was created. This field can be used as a filter in list requests.
	CreateTime *strfmt.DateTime `json:"create_time,omitempty"`

	// Output only. The time this note was last updated. This field can be used as a filter in list requests.
	UpdateTime *strfmt.DateTime `json:"update_time,omitempty"`

	// True if this `Note` can be shared by multiple accounts.
	Shared *bool `json:"shared,omitempty"`

	// The finding details of the note.
	Finding *FindingType `json:"finding,omitempty"`

	// The KPI details of the note.
	Kpi *KpiType `json:"kpi,omitempty"`

	// The card details of the note.
	Card *Card `json:"card,omitempty"`

	// The section details of the note.
	Section *Section `json:"section,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewCreateNoteOptions : Instantiate CreateNoteOptions
func (findingsApi *FindingsApiV1) NewCreateNoteOptions(accountID string, providerID string, shortDescription string, longDescription string, kind string, ID string, reportedBy *Reporter) *CreateNoteOptions {
	return &CreateNoteOptions{
		AccountID:        core.StringPtr(accountID),
		ProviderID:       core.StringPtr(providerID),
		ShortDescription: core.StringPtr(shortDescription),
		LongDescription:  core.StringPtr(longDescription),
		Kind:             core.StringPtr(kind),
		ID:               core.StringPtr(ID),
		ReportedBy:       reportedBy,
	}
}

// SetAccountID : Allow user to set AccountID
func (options *CreateNoteOptions) SetAccountID(accountID string) *CreateNoteOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *CreateNoteOptions) SetProviderID(providerID string) *CreateNoteOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetShortDescription : Allow user to set ShortDescription
func (options *CreateNoteOptions) SetShortDescription(shortDescription string) *CreateNoteOptions {
	options.ShortDescription = core.StringPtr(shortDescription)
	return options
}

// SetLongDescription : Allow user to set LongDescription
func (options *CreateNoteOptions) SetLongDescription(longDescription string) *CreateNoteOptions {
	options.LongDescription = core.StringPtr(longDescription)
	return options
}

// SetKind : Allow user to set Kind
func (options *CreateNoteOptions) SetKind(kind *string) *CreateNoteOptions {
	options.Kind = kind
	return options
}

// SetID : Allow user to set ID
func (options *CreateNoteOptions) SetID(ID string) *CreateNoteOptions {
	options.ID = core.StringPtr(ID)
	return options
}

// SetReportedBy : Allow user to set ReportedBy
func (options *CreateNoteOptions) SetReportedBy(reportedBy *Reporter) *CreateNoteOptions {
	options.ReportedBy = reportedBy
	return options
}

// SetRelatedURL : Allow user to set RelatedURL
func (options *CreateNoteOptions) SetRelatedURL(relatedURL []ApiNoteRelatedURL) *CreateNoteOptions {
	options.RelatedURL = relatedURL
	return options
}

// SetExpirationTime : Allow user to set ExpirationTime
func (options *CreateNoteOptions) SetExpirationTime(expirationTime *strfmt.DateTime) *CreateNoteOptions {
	options.ExpirationTime = expirationTime
	return options
}

// SetCreateTime : Allow user to set CreateTime
func (options *CreateNoteOptions) SetCreateTime(createTime *strfmt.DateTime) *CreateNoteOptions {
	options.CreateTime = createTime
	return options
}

// SetUpdateTime : Allow user to set UpdateTime
func (options *CreateNoteOptions) SetUpdateTime(updateTime *strfmt.DateTime) *CreateNoteOptions {
	options.UpdateTime = updateTime
	return options
}

// SetShared : Allow user to set Shared
func (options *CreateNoteOptions) SetShared(shared bool) *CreateNoteOptions {
	options.Shared = core.BoolPtr(shared)
	return options
}

// SetFinding : Allow user to set Finding
func (options *CreateNoteOptions) SetFinding(finding *FindingType) *CreateNoteOptions {
	options.Finding = finding
	return options
}

// SetKpi : Allow user to set Kpi
func (options *CreateNoteOptions) SetKpi(kpi *KpiType) *CreateNoteOptions {
	options.Kpi = kpi
	return options
}

// SetCard : Allow user to set Card
func (options *CreateNoteOptions) SetCard(card *Card) *CreateNoteOptions {
	options.Card = card
	return options
}

// SetSection : Allow user to set Section
func (options *CreateNoteOptions) SetSection(section *Section) *CreateNoteOptions {
	options.Section = section
	return options
}

// SetHeaders : Allow user to set Headers
func (options *CreateNoteOptions) SetHeaders(param map[string]string) *CreateNoteOptions {
	options.Headers = param
	return options
}

// CreateOccurrenceOptions : The CreateOccurrence options.
type CreateOccurrenceOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Part of `parent`. This contains the provider_id for example: providers/{provider_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// An analysis note associated with this image, in the form "{account_id}/providers/{provider_id}/notes/{note_id}" This
	// field can be used as a filter in list requests.
	NoteName *string `json:"note_name" validate:"required"`

	// Output only. This explicitly denotes which of the `Occurrence` details are specified.
	// This field can be used as a filter in list requests.
	Kind *string `json:"kind" validate:"required"`

	ID *string `json:"id" validate:"required"`

	// The unique URL of the resource, image or the container, for which the `Occurrence` applies. For example,
	// https://gcr.io/provider/image@sha256:foo. This field can be used as a filter in list requests.
	ResourceURL *string `json:"resource_url,omitempty"`

	Remediation *string `json:"remediation,omitempty"`

	// Output only. The time this `Occurrence` was created.
	CreateTime *strfmt.DateTime `json:"create_time,omitempty"`

	// Output only. The time this `Occurrence` was last updated.
	UpdateTime *strfmt.DateTime `json:"update_time,omitempty"`

	// Details about the context of this `Occurrence`.
	Context *Context `json:"context,omitempty"`

	// Details of the occurrence of a finding.
	Finding *Finding `json:"finding,omitempty"`

	// Details of the occurrence of a KPI.
	Kpi *Kpi `json:"kpi,omitempty"`

	// It allows replacing an existing occurrence when set to true.
	ReplaceIfExists *bool `json:"Replace-If-Exists,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewCreateOccurrenceOptions : Instantiate CreateOccurrenceOptions
func (findingsApi *FindingsApiV1) NewCreateOccurrenceOptions(accountID string, providerID string, noteName string, kind string, ID string) *CreateOccurrenceOptions {
	return &CreateOccurrenceOptions{
		AccountID:  core.StringPtr(accountID),
		ProviderID: core.StringPtr(providerID),
		NoteName:   core.StringPtr(noteName),
		Kind:       core.StringPtr(kind),
		ID:         core.StringPtr(ID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *CreateOccurrenceOptions) SetAccountID(accountID string) *CreateOccurrenceOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *CreateOccurrenceOptions) SetProviderID(providerID string) *CreateOccurrenceOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetNoteName : Allow user to set NoteName
func (options *CreateOccurrenceOptions) SetNoteName(noteName string) *CreateOccurrenceOptions {
	options.NoteName = core.StringPtr(noteName)
	return options
}

// SetKind : Allow user to set Kind
func (options *CreateOccurrenceOptions) SetKind(kind string) *CreateOccurrenceOptions {
	options.Kind = core.StringPtr(kind)
	return options
}

// SetID : Allow user to set ID
func (options *CreateOccurrenceOptions) SetID(ID string) *CreateOccurrenceOptions {
	options.ID = core.StringPtr(ID)
	return options
}

// SetResourceURL : Allow user to set ResourceURL
func (options *CreateOccurrenceOptions) SetResourceURL(resourceURL string) *CreateOccurrenceOptions {
	options.ResourceURL = core.StringPtr(resourceURL)
	return options
}

// SetRemediation : Allow user to set Remediation
func (options *CreateOccurrenceOptions) SetRemediation(remediation string) *CreateOccurrenceOptions {
	options.Remediation = core.StringPtr(remediation)
	return options
}

// SetCreateTime : Allow user to set CreateTime
func (options *CreateOccurrenceOptions) SetCreateTime(createTime *strfmt.DateTime) *CreateOccurrenceOptions {
	options.CreateTime = createTime
	return options
}

// SetUpdateTime : Allow user to set UpdateTime
func (options *CreateOccurrenceOptions) SetUpdateTime(updateTime *strfmt.DateTime) *CreateOccurrenceOptions {
	options.UpdateTime = updateTime
	return options
}

// SetContext : Allow user to set Context
func (options *CreateOccurrenceOptions) SetContext(context *Context) *CreateOccurrenceOptions {
	options.Context = context
	return options
}

// SetFinding : Allow user to set Finding
func (options *CreateOccurrenceOptions) SetFinding(finding *Finding) *CreateOccurrenceOptions {
	options.Finding = finding
	return options
}

// SetKpi : Allow user to set Kpi
func (options *CreateOccurrenceOptions) SetKpi(kpi *Kpi) *CreateOccurrenceOptions {
	options.Kpi = kpi
	return options
}

// SetReplaceIfExists : Allow user to set ReplaceIfExists
func (options *CreateOccurrenceOptions) SetReplaceIfExists(replaceIfExists bool) *CreateOccurrenceOptions {
	options.ReplaceIfExists = core.BoolPtr(replaceIfExists)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *CreateOccurrenceOptions) SetHeaders(param map[string]string) *CreateOccurrenceOptions {
	options.Headers = param
	return options
}

// DataTransferred : It provides details about data transferred between clients and servers.
type DataTransferred struct {

	// The number of client bytes transferred.
	ClientBytes *int64 `json:"client_bytes,omitempty"`

	// The number of server bytes transferred.
	ServerBytes *int64 `json:"server_bytes,omitempty"`

	// The number of client packets transferred.
	ClientPackets *int64 `json:"client_packets,omitempty"`

	// The number of server packets transferred.
	ServerPackets *int64 `json:"server_packets,omitempty"`
}

// DeleteNoteOptions : The DeleteNote options.
type DeleteNoteOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// First part of note `name`: providers/{provider_id}/notes/{note_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// Second part of note `name`: providers/{provider_id}/notes/{note_id}.
	NoteID *string `json:"note_id" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewDeleteNoteOptions : Instantiate DeleteNoteOptions
func (findingsApi *FindingsApiV1) NewDeleteNoteOptions(accountID string, providerID string, noteID string) *DeleteNoteOptions {
	return &DeleteNoteOptions{
		AccountID:  core.StringPtr(accountID),
		ProviderID: core.StringPtr(providerID),
		NoteID:     core.StringPtr(noteID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *DeleteNoteOptions) SetAccountID(accountID string) *DeleteNoteOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *DeleteNoteOptions) SetProviderID(providerID string) *DeleteNoteOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetNoteID : Allow user to set NoteID
func (options *DeleteNoteOptions) SetNoteID(noteID string) *DeleteNoteOptions {
	options.NoteID = core.StringPtr(noteID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteNoteOptions) SetHeaders(param map[string]string) *DeleteNoteOptions {
	options.Headers = param
	return options
}

// DeleteOccurrenceOptions : The DeleteOccurrence options.
type DeleteOccurrenceOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// First part of occurrence `name`: providers/{provider_id}/notes/{occurrence_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// Second part of occurrence `name`: providers/{provider_id}/notes/{occurrence_id}.
	OccurrenceID *string `json:"occurrence_id" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewDeleteOccurrenceOptions : Instantiate DeleteOccurrenceOptions
func (findingsApi *FindingsApiV1) NewDeleteOccurrenceOptions(accountID string, providerID string, occurrenceID string) *DeleteOccurrenceOptions {
	return &DeleteOccurrenceOptions{
		AccountID:    core.StringPtr(accountID),
		ProviderID:   core.StringPtr(providerID),
		OccurrenceID: core.StringPtr(occurrenceID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *DeleteOccurrenceOptions) SetAccountID(accountID string) *DeleteOccurrenceOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *DeleteOccurrenceOptions) SetProviderID(providerID string) *DeleteOccurrenceOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetOccurrenceID : Allow user to set OccurrenceID
func (options *DeleteOccurrenceOptions) SetOccurrenceID(occurrenceID string) *DeleteOccurrenceOptions {
	options.OccurrenceID = core.StringPtr(occurrenceID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteOccurrenceOptions) SetHeaders(param map[string]string) *DeleteOccurrenceOptions {
	options.Headers = param
	return options
}

// Finding : Finding provides details about a finding occurrence.
type Finding struct {

	// Severity : Note provider-assigned severity/impact ranking
	// - LOW&#58; Low Impact
	// - MEDIUM&#58; Medium Impact
	// - HIGH&#58; High Impact.
	Severity *string `json:"severity,omitempty"`

	// Certainty : Note provider-assigned confidence on the validity of an occurrence
	// - LOW&#58; Low Certainty
	// - MEDIUM&#58; Medium Certainty
	// - HIGH&#58; High Certainty.
	Certainty *string `json:"certainty,omitempty"`

	// Remediation steps for the issues reported in this finding. They override the note's next steps.
	NextSteps []RemediationStep `json:"next_steps,omitempty"`

	// Network connection details of this finding.
	NetworkConnection *NetworkConnection `json:"network_connection,omitempty"`

	// Data transferred details of this finding.
	DataTransferred *DataTransferred `json:"data_transferred,omitempty"`
}

// FindingCountValueType : FindingCountValueType struct
type FindingCountValueType struct {

	// Kind of element
	// - FINDING_COUNT&#58; Kind of value derived from a count of finding occurrences.
	Kind *string `json:"kind" validate:"required"`

	// the names of the finding note associated that act as filters for counting the occurrences.
	FindingNoteNames []string `json:"finding_note_names" validate:"required"`

	// The text of this element type.
	Text *string `json:"text" validate:"required"`
}

// Constants associated with the FindingCountValueType.Kind property.
// Kind of element
// - FINDING_COUNT&#58; Kind of value derived from a count of finding occurrences.
const (
	FindingCountValueType_Kind_FindingCount = "FINDING_COUNT"
)

// NewFindingCountValueType : Instantiate FindingCountValueType (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewFindingCountValueType(kind string, findingNoteNames []string, text string) (model *FindingCountValueType, err error) {
	model = &FindingCountValueType{
		Kind:             core.StringPtr(kind),
		FindingNoteNames: findingNoteNames,
		Text:             core.StringPtr(text),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// FindingType : FindingType provides details about a finding note.
type FindingType struct {

	// The default severity of the findings related to this `Note`.
	Severity *string `json:"severity" validate:"required"`

	// Common remediation steps for the finding of this type.
	NextSteps []RemediationStep `json:"next_steps,omitempty"`
}

// NewFindingType : Instantiate FindingType (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewFindingType(severity *string) (model *FindingType, err error) {
	model = &FindingType{
		Severity: severity,
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// GetNoteOptions : The GetNote options.
type GetNoteOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// First part of note `name`: providers/{provider_id}/notes/{note_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// Second part of note `name`: providers/{provider_id}/notes/{note_id}.
	NoteID *string `json:"note_id" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetNoteOptions : Instantiate GetNoteOptions
func (findingsApi *FindingsApiV1) NewGetNoteOptions(accountID string, providerID string, noteID string) *GetNoteOptions {
	return &GetNoteOptions{
		AccountID:  core.StringPtr(accountID),
		ProviderID: core.StringPtr(providerID),
		NoteID:     core.StringPtr(noteID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *GetNoteOptions) SetAccountID(accountID string) *GetNoteOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *GetNoteOptions) SetProviderID(providerID string) *GetNoteOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetNoteID : Allow user to set NoteID
func (options *GetNoteOptions) SetNoteID(noteID string) *GetNoteOptions {
	options.NoteID = core.StringPtr(noteID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetNoteOptions) SetHeaders(param map[string]string) *GetNoteOptions {
	options.Headers = param
	return options
}

// GetOccurrenceNoteOptions : The GetOccurrenceNote options.
type GetOccurrenceNoteOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// First part of occurrence `name`: providers/{provider_id}/occurrences/{occurrence_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// Second part of occurrence `name`: providers/{provider_id}/occurrences/{occurrence_id}.
	OccurrenceID *string `json:"occurrence_id" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetOccurrenceNoteOptions : Instantiate GetOccurrenceNoteOptions
func (findingsApi *FindingsApiV1) NewGetOccurrenceNoteOptions(accountID string, providerID string, occurrenceID string) *GetOccurrenceNoteOptions {
	return &GetOccurrenceNoteOptions{
		AccountID:    core.StringPtr(accountID),
		ProviderID:   core.StringPtr(providerID),
		OccurrenceID: core.StringPtr(occurrenceID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *GetOccurrenceNoteOptions) SetAccountID(accountID string) *GetOccurrenceNoteOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *GetOccurrenceNoteOptions) SetProviderID(providerID string) *GetOccurrenceNoteOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetOccurrenceID : Allow user to set OccurrenceID
func (options *GetOccurrenceNoteOptions) SetOccurrenceID(occurrenceID string) *GetOccurrenceNoteOptions {
	options.OccurrenceID = core.StringPtr(occurrenceID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetOccurrenceNoteOptions) SetHeaders(param map[string]string) *GetOccurrenceNoteOptions {
	options.Headers = param
	return options
}

// GetOccurrenceOptions : The GetOccurrence options.
type GetOccurrenceOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// First part of occurrence `name`: providers/{provider_id}/occurrences/{occurrence_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// Second part of occurrence `name`: providers/{provider_id}/occurrences/{occurrence_id}.
	OccurrenceID *string `json:"occurrence_id" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetOccurrenceOptions : Instantiate GetOccurrenceOptions
func (findingsApi *FindingsApiV1) NewGetOccurrenceOptions(accountID string, providerID string, occurrenceID string) *GetOccurrenceOptions {
	return &GetOccurrenceOptions{
		AccountID:    core.StringPtr(accountID),
		ProviderID:   core.StringPtr(providerID),
		OccurrenceID: core.StringPtr(occurrenceID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *GetOccurrenceOptions) SetAccountID(accountID string) *GetOccurrenceOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *GetOccurrenceOptions) SetProviderID(providerID string) *GetOccurrenceOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetOccurrenceID : Allow user to set OccurrenceID
func (options *GetOccurrenceOptions) SetOccurrenceID(occurrenceID string) *GetOccurrenceOptions {
	options.OccurrenceID = core.StringPtr(occurrenceID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetOccurrenceOptions) SetHeaders(param map[string]string) *GetOccurrenceOptions {
	options.Headers = param
	return options
}

// Kpi : Kpi provides details about a KPI occurrence.
type Kpi struct {

	// The value of this KPI.
	Value *float64 `json:"value" validate:"required"`

	// The total value of this KPI.
	Total *float64 `json:"total,omitempty"`
}

// NewKpi : Instantiate Kpi (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewKpi(value float64) (model *Kpi, err error) {
	model = &Kpi{
		Value: core.Float64Ptr(value),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// KpiType : KpiType provides details about a KPI note.
type KpiType struct {

	// The aggregation type of the KPI values.
	// - SUM&#58; A single-value metrics aggregation type that sums up numeric values
	//   that are extracted from KPI occurrences.
	AggregationType *string `json:"aggregation_type" validate:"required"`
}

// Constants associated with the KpiType.AggregationType property.
// The aggregation type of the KPI values.
// - SUM&#58; A single-value metrics aggregation type that sums up numeric values
//   that are extracted from KPI occurrences.
const (
	KpiType_AggregationType_Sum = "SUM"
)

// NewKpiType : Instantiate KpiType (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewKpiType(aggregationType string) (model *KpiType, err error) {
	model = &KpiType{
		AggregationType: core.StringPtr(aggregationType),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// ListNoteOccurrencesOptions : The ListNoteOccurrences options.
type ListNoteOccurrencesOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// First part of note `name`: providers/{provider_id}/notes/{note_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// Second part of note `name`: providers/{provider_id}/notes/{note_id}.
	NoteID *string `json:"note_id" validate:"required"`

	// Number of notes to return in the list.
	PageSize *int64 `json:"page_size,omitempty"`

	// Token to provide to skip to a particular spot in the list.
	PageToken *string `json:"page_token,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewListNoteOccurrencesOptions : Instantiate ListNoteOccurrencesOptions
func (findingsApi *FindingsApiV1) NewListNoteOccurrencesOptions(accountID string, providerID string, noteID string) *ListNoteOccurrencesOptions {
	return &ListNoteOccurrencesOptions{
		AccountID:  core.StringPtr(accountID),
		ProviderID: core.StringPtr(providerID),
		NoteID:     core.StringPtr(noteID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *ListNoteOccurrencesOptions) SetAccountID(accountID string) *ListNoteOccurrencesOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *ListNoteOccurrencesOptions) SetProviderID(providerID string) *ListNoteOccurrencesOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetNoteID : Allow user to set NoteID
func (options *ListNoteOccurrencesOptions) SetNoteID(noteID string) *ListNoteOccurrencesOptions {
	options.NoteID = core.StringPtr(noteID)
	return options
}

// SetPageSize : Allow user to set PageSize
func (options *ListNoteOccurrencesOptions) SetPageSize(pageSize int64) *ListNoteOccurrencesOptions {
	options.PageSize = core.Int64Ptr(pageSize)
	return options
}

// SetPageToken : Allow user to set PageToken
func (options *ListNoteOccurrencesOptions) SetPageToken(pageToken string) *ListNoteOccurrencesOptions {
	options.PageToken = core.StringPtr(pageToken)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *ListNoteOccurrencesOptions) SetHeaders(param map[string]string) *ListNoteOccurrencesOptions {
	options.Headers = param
	return options
}

// ListNotesOptions : The ListNotes options.
type ListNotesOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Part of `parent`. This field contains the provider_id for example: providers/{provider_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// Number of notes to return in the list.
	PageSize *int64 `json:"page_size,omitempty"`

	// Token to provide to skip to a particular spot in the list.
	PageToken *string `json:"page_token,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewListNotesOptions : Instantiate ListNotesOptions
func (findingsApi *FindingsApiV1) NewListNotesOptions(accountID string, providerID string) *ListNotesOptions {
	return &ListNotesOptions{
		AccountID:  core.StringPtr(accountID),
		ProviderID: core.StringPtr(providerID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *ListNotesOptions) SetAccountID(accountID string) *ListNotesOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *ListNotesOptions) SetProviderID(providerID string) *ListNotesOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetPageSize : Allow user to set PageSize
func (options *ListNotesOptions) SetPageSize(pageSize int64) *ListNotesOptions {
	options.PageSize = core.Int64Ptr(pageSize)
	return options
}

// SetPageToken : Allow user to set PageToken
func (options *ListNotesOptions) SetPageToken(pageToken string) *ListNotesOptions {
	options.PageToken = core.StringPtr(pageToken)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *ListNotesOptions) SetHeaders(param map[string]string) *ListNotesOptions {
	options.Headers = param
	return options
}

// ListOccurrencesOptions : The ListOccurrences options.
type ListOccurrencesOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Part of `parent`. This contains the provider_id for example: providers/{provider_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// Number of occurrences to return in the list.
	PageSize *int64 `json:"page_size,omitempty"`

	// Token to provide to skip to a particular spot in the list.
	PageToken *string `json:"page_token,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewListOccurrencesOptions : Instantiate ListOccurrencesOptions
func (findingsApi *FindingsApiV1) NewListOccurrencesOptions(accountID string, providerID string) *ListOccurrencesOptions {
	return &ListOccurrencesOptions{
		AccountID:  core.StringPtr(accountID),
		ProviderID: core.StringPtr(providerID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *ListOccurrencesOptions) SetAccountID(accountID string) *ListOccurrencesOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *ListOccurrencesOptions) SetProviderID(providerID string) *ListOccurrencesOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetPageSize : Allow user to set PageSize
func (options *ListOccurrencesOptions) SetPageSize(pageSize int64) *ListOccurrencesOptions {
	options.PageSize = core.Int64Ptr(pageSize)
	return options
}

// SetPageToken : Allow user to set PageToken
func (options *ListOccurrencesOptions) SetPageToken(pageToken string) *ListOccurrencesOptions {
	options.PageToken = core.StringPtr(pageToken)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *ListOccurrencesOptions) SetHeaders(param map[string]string) *ListOccurrencesOptions {
	options.Headers = param
	return options
}

// ListProvidersOptions : The ListProviders options.
type ListProvidersOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Limit the number of the returned documents to the specified number.
	Limit *int64 `json:"limit,omitempty"`

	// The offset is the index of the item from which you want to start returning data from. Default is 0.
	Skip *int64 `json:"skip,omitempty"`

	// The first provider_id to include in the result (sorted in ascending order). Ignored if not provided.
	StartProviderID *string `json:"start_provider_id,omitempty"`

	// The last provider_id to include in the result (sorted in ascending order). Ignored if not provided.
	EndProviderID *string `json:"end_provider_id,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewListProvidersOptions : Instantiate ListProvidersOptions
func (findingsApi *FindingsApiV1) NewListProvidersOptions(accountID string) *ListProvidersOptions {
	return &ListProvidersOptions{
		AccountID: core.StringPtr(accountID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *ListProvidersOptions) SetAccountID(accountID string) *ListProvidersOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetLimit : Allow user to set Limit
func (options *ListProvidersOptions) SetLimit(limit int64) *ListProvidersOptions {
	options.Limit = core.Int64Ptr(limit)
	return options
}

// SetSkip : Allow user to set Skip
func (options *ListProvidersOptions) SetSkip(skip int64) *ListProvidersOptions {
	options.Skip = core.Int64Ptr(skip)
	return options
}

// SetStartProviderID : Allow user to set StartProviderID
func (options *ListProvidersOptions) SetStartProviderID(startProviderID string) *ListProvidersOptions {
	options.StartProviderID = core.StringPtr(startProviderID)
	return options
}

// SetEndProviderID : Allow user to set EndProviderID
func (options *ListProvidersOptions) SetEndProviderID(endProviderID string) *ListProvidersOptions {
	options.EndProviderID = core.StringPtr(endProviderID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *ListProvidersOptions) SetHeaders(param map[string]string) *ListProvidersOptions {
	options.Headers = param
	return options
}

// NetworkConnection : It provides details about a network connection.
type NetworkConnection struct {

	// The direction of this network connection.
	Direction *string `json:"direction,omitempty"`

	// The protocol of this network connection.
	Protocol *string `json:"protocol,omitempty"`

	// The client socket address of this network connection.
	Client *SocketAddress `json:"client,omitempty"`

	// The server socket address of this network connection.
	Server *SocketAddress `json:"server,omitempty"`
}

// PostGraphOptions : The PostGraph options.
type PostGraphOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Body for query findings.
	Body io.ReadCloser `json:"body,omitempty"`

	// The type of the input.
	ContentType *string `json:"Content-Type,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewPostGraphOptions : Instantiate PostGraphOptions
func (findingsApi *FindingsApiV1) NewPostGraphOptions(accountID string) *PostGraphOptions {
	return &PostGraphOptions{
		AccountID: core.StringPtr(accountID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *PostGraphOptions) SetAccountID(accountID string) *PostGraphOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetBody : Allow user to set Body
func (options *PostGraphOptions) SetBody(body io.ReadCloser) *PostGraphOptions {
	options.Body = body
	return options
}

// SetContentType : Allow user to set ContentType
func (options *PostGraphOptions) SetContentType(contentType string) *PostGraphOptions {
	options.ContentType = core.StringPtr(contentType)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *PostGraphOptions) SetHeaders(param map[string]string) *PostGraphOptions {
	options.Headers = param
	return options
}

// RemediationStep : A remediation step description and associated URL.
type RemediationStep struct {

	// Title of this next step.
	Title *string `json:"title,omitempty"`

	// The URL associated to this next steps.
	URL *string `json:"url,omitempty"`
}

// Reporter : The entity reporting a note.
type Reporter struct {

	// The id of this reporter.
	ID *string `json:"id" validate:"required"`

	// The title of this reporter.
	Title *string `json:"title" validate:"required"`

	// The url of this reporter.
	URL *string `json:"url,omitempty"`
}

// NewReporter : Instantiate Reporter (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewReporter(ID string, title string) (model *Reporter, err error) {
	model = &Reporter{
		ID:    core.StringPtr(ID),
		Title: core.StringPtr(title),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// Section : Card provides details about a card kind of note.
type Section struct {

	// The title of this section.
	Title *string `json:"title" validate:"required"`

	// The image of this section.
	Image *string `json:"image" validate:"required"`
}

// NewSection : Instantiate Section (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewSection(title string, image string) (model *Section, err error) {
	model = &Section{
		Title: core.StringPtr(title),
		Image: core.StringPtr(image),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// Severity : Note provider-assigned severity/impact ranking
// - LOW&#58; Low Impact
// - MEDIUM&#58; Medium Impact
// - HIGH&#58; High Impact.
// - CRITICAL&#58; Critical Impact.
type Severity struct {
}

// SocketAddress : It provides details about a socket address.
type SocketAddress struct {

	// The IP address of this socket address.
	Address *string `json:"address" validate:"required"`

	// The port number of this socket address.
	Port *int64 `json:"port,omitempty"`
}

// NewSocketAddress : Instantiate SocketAddress (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewSocketAddress(address string) (model *SocketAddress, err error) {
	model = &SocketAddress{
		Address: core.StringPtr(address),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// UpdateNoteOptions : The UpdateNote options.
type UpdateNoteOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// First part of note `name`: providers/{provider_id}/notes/{note_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// Second part of note `name`: providers/{provider_id}/notes/{note_id}.
	NoteID *string `json:"note_id" validate:"required"`

	// A one sentence description of this `Note`.
	ShortDescription *string `json:"short_description" validate:"required"`

	// A detailed description of this `Note`.
	LongDescription *string `json:"long_description" validate:"required"`

	// Output only. This explicitly denotes which kind of note is specified. This
	// field can be used as a filter in list requests.
	Kind *string `json:"kind" validate:"required"`

	ID *string `json:"id" validate:"required"`

	// Details about the reporter of this `Note`.
	ReportedBy *Reporter `json:"reported_by" validate:"required"`

	RelatedURL []ApiNoteRelatedURL `json:"related_url,omitempty"`

	// Time of expiration for this note, null if note does not expire.
	ExpirationTime *strfmt.DateTime `json:"expiration_time,omitempty"`

	// Output only. The time this note was created. This field can be used as a filter in list requests.
	CreateTime *strfmt.DateTime `json:"create_time,omitempty"`

	// Output only. The time this note was last updated. This field can be used as a filter in list requests.
	UpdateTime *strfmt.DateTime `json:"update_time,omitempty"`

	// True if this `Note` can be shared by multiple accounts.
	Shared *bool `json:"shared,omitempty"`

	// The finding details of the note.
	Finding *FindingType `json:"finding,omitempty"`

	// The KPI details of the note.
	Kpi *KpiType `json:"kpi,omitempty"`

	// The card details of the note.
	Card *Card `json:"card,omitempty"`

	// The section details of the note.
	Section *Section `json:"section,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewUpdateNoteOptions : Instantiate UpdateNoteOptions
func (findingsApi *FindingsApiV1) NewUpdateNoteOptions(accountID string, providerID string, noteID string, shortDescription string, longDescription string, kind string, ID string, reportedBy *Reporter) *UpdateNoteOptions {
	return &UpdateNoteOptions{
		AccountID:        core.StringPtr(accountID),
		ProviderID:       core.StringPtr(providerID),
		NoteID:           core.StringPtr(noteID),
		ShortDescription: core.StringPtr(shortDescription),
		LongDescription:  core.StringPtr(longDescription),
		Kind:             core.StringPtr(kind),
		ID:               core.StringPtr(ID),
		ReportedBy:       reportedBy,
	}
}

// SetAccountID : Allow user to set AccountID
func (options *UpdateNoteOptions) SetAccountID(accountID string) *UpdateNoteOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *UpdateNoteOptions) SetProviderID(providerID string) *UpdateNoteOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetNoteID : Allow user to set NoteID
func (options *UpdateNoteOptions) SetNoteID(noteID string) *UpdateNoteOptions {
	options.NoteID = core.StringPtr(noteID)
	return options
}

// SetShortDescription : Allow user to set ShortDescription
func (options *UpdateNoteOptions) SetShortDescription(shortDescription string) *UpdateNoteOptions {
	options.ShortDescription = core.StringPtr(shortDescription)
	return options
}

// SetLongDescription : Allow user to set LongDescription
func (options *UpdateNoteOptions) SetLongDescription(longDescription string) *UpdateNoteOptions {
	options.LongDescription = core.StringPtr(longDescription)
	return options
}

// SetKind : Allow user to set Kind
func (options *UpdateNoteOptions) SetKind(kind string) *UpdateNoteOptions {
	options.Kind = core.StringPtr(kind)
	return options
}

// SetID : Allow user to set ID
func (options *UpdateNoteOptions) SetID(ID string) *UpdateNoteOptions {
	options.ID = core.StringPtr(ID)
	return options
}

// SetReportedBy : Allow user to set ReportedBy
func (options *UpdateNoteOptions) SetReportedBy(reportedBy *Reporter) *UpdateNoteOptions {
	options.ReportedBy = reportedBy
	return options
}

// SetRelatedURL : Allow user to set RelatedURL
func (options *UpdateNoteOptions) SetRelatedURL(relatedURL []ApiNoteRelatedURL) *UpdateNoteOptions {
	options.RelatedURL = relatedURL
	return options
}

// SetExpirationTime : Allow user to set ExpirationTime
func (options *UpdateNoteOptions) SetExpirationTime(expirationTime *strfmt.DateTime) *UpdateNoteOptions {
	options.ExpirationTime = expirationTime
	return options
}

// SetCreateTime : Allow user to set CreateTime
func (options *UpdateNoteOptions) SetCreateTime(createTime *strfmt.DateTime) *UpdateNoteOptions {
	options.CreateTime = createTime
	return options
}

// SetUpdateTime : Allow user to set UpdateTime
func (options *UpdateNoteOptions) SetUpdateTime(updateTime *strfmt.DateTime) *UpdateNoteOptions {
	options.UpdateTime = updateTime
	return options
}

// SetShared : Allow user to set Shared
func (options *UpdateNoteOptions) SetShared(shared bool) *UpdateNoteOptions {
	options.Shared = core.BoolPtr(shared)
	return options
}

// SetFinding : Allow user to set Finding
func (options *UpdateNoteOptions) SetFinding(finding *FindingType) *UpdateNoteOptions {
	options.Finding = finding
	return options
}

// SetKpi : Allow user to set Kpi
func (options *UpdateNoteOptions) SetKpi(kpi *KpiType) *UpdateNoteOptions {
	options.Kpi = kpi
	return options
}

// SetCard : Allow user to set Card
func (options *UpdateNoteOptions) SetCard(card *Card) *UpdateNoteOptions {
	options.Card = card
	return options
}

// SetSection : Allow user to set Section
func (options *UpdateNoteOptions) SetSection(section *Section) *UpdateNoteOptions {
	options.Section = section
	return options
}

// SetHeaders : Allow user to set Headers
func (options *UpdateNoteOptions) SetHeaders(param map[string]string) *UpdateNoteOptions {
	options.Headers = param
	return options
}

// UpdateOccurrenceOptions : The UpdateOccurrence options.
type UpdateOccurrenceOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// First part of occurrence `name`: providers/{provider_id}/occurrences/{occurrence_id}.
	ProviderID *string `json:"provider_id" validate:"required"`

	// Second part of occurrence `name`: providers/{provider_id}/occurrences/{occurrence_id}.
	OccurrenceID *string `json:"occurrence_id" validate:"required"`

	// An analysis note associated with this image, in the form "{account_id}/providers/{provider_id}/notes/{note_id}" This
	// field can be used as a filter in list requests.
	NoteName *string `json:"note_name" validate:"required"`

	// Output only. This explicitly denotes which of the `Occurrence` details are specified.
	// This field can be used as a filter in list requests.
	Kind *string `json:"kind" validate:"required"`

	ID *string `json:"id" validate:"required"`

	// The unique URL of the resource, image or the container, for which the `Occurrence` applies. For example,
	// https://gcr.io/provider/image@sha256:foo. This field can be used as a filter in list requests.
	ResourceURL *string `json:"resource_url,omitempty"`

	Remediation *string `json:"remediation,omitempty"`

	// Output only. The time this `Occurrence` was created.
	CreateTime *strfmt.DateTime `json:"create_time,omitempty"`

	// Output only. The time this `Occurrence` was last updated.
	UpdateTime *strfmt.DateTime `json:"update_time,omitempty"`

	// Details about the context of this `Occurrence`.
	Context *Context `json:"context,omitempty"`

	// Details of the occurrence of a finding.
	Finding *Finding `json:"finding,omitempty"`

	// Details of the occurrence of a KPI.
	Kpi *Kpi `json:"kpi,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewUpdateOccurrenceOptions : Instantiate UpdateOccurrenceOptions
func (findingsApi *FindingsApiV1) NewUpdateOccurrenceOptions(accountID string, providerID string, occurrenceID string, noteName string, kind string, ID string) *UpdateOccurrenceOptions {
	return &UpdateOccurrenceOptions{
		AccountID:    core.StringPtr(accountID),
		ProviderID:   core.StringPtr(providerID),
		OccurrenceID: core.StringPtr(occurrenceID),
		NoteName:     core.StringPtr(noteName),
		Kind:         core.StringPtr(kind),
		ID:           core.StringPtr(ID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *UpdateOccurrenceOptions) SetAccountID(accountID string) *UpdateOccurrenceOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetProviderID : Allow user to set ProviderID
func (options *UpdateOccurrenceOptions) SetProviderID(providerID string) *UpdateOccurrenceOptions {
	options.ProviderID = core.StringPtr(providerID)
	return options
}

// SetOccurrenceID : Allow user to set OccurrenceID
func (options *UpdateOccurrenceOptions) SetOccurrenceID(occurrenceID string) *UpdateOccurrenceOptions {
	options.OccurrenceID = core.StringPtr(occurrenceID)
	return options
}

// SetNoteName : Allow user to set NoteName
func (options *UpdateOccurrenceOptions) SetNoteName(noteName string) *UpdateOccurrenceOptions {
	options.NoteName = core.StringPtr(noteName)
	return options
}

// SetKind : Allow user to set Kind
func (options *UpdateOccurrenceOptions) SetKind(kind string) *UpdateOccurrenceOptions {
	options.Kind = core.StringPtr(kind)
	return options
}

// SetID : Allow user to set ID
func (options *UpdateOccurrenceOptions) SetID(ID string) *UpdateOccurrenceOptions {
	options.ID = core.StringPtr(ID)
	return options
}

// SetResourceURL : Allow user to set ResourceURL
func (options *UpdateOccurrenceOptions) SetResourceURL(resourceURL string) *UpdateOccurrenceOptions {
	options.ResourceURL = core.StringPtr(resourceURL)
	return options
}

// SetRemediation : Allow user to set Remediation
func (options *UpdateOccurrenceOptions) SetRemediation(remediation string) *UpdateOccurrenceOptions {
	options.Remediation = core.StringPtr(remediation)
	return options
}

// SetCreateTime : Allow user to set CreateTime
func (options *UpdateOccurrenceOptions) SetCreateTime(createTime *strfmt.DateTime) *UpdateOccurrenceOptions {
	options.CreateTime = createTime
	return options
}

// SetUpdateTime : Allow user to set UpdateTime
func (options *UpdateOccurrenceOptions) SetUpdateTime(updateTime *strfmt.DateTime) *UpdateOccurrenceOptions {
	options.UpdateTime = updateTime
	return options
}

// SetContext : Allow user to set Context
func (options *UpdateOccurrenceOptions) SetContext(context *Context) *UpdateOccurrenceOptions {
	options.Context = context
	return options
}

// SetFinding : Allow user to set Finding
func (options *UpdateOccurrenceOptions) SetFinding(finding *Finding) *UpdateOccurrenceOptions {
	options.Finding = finding
	return options
}

// SetKpi : Allow user to set Kpi
func (options *UpdateOccurrenceOptions) SetKpi(kpi *Kpi) *UpdateOccurrenceOptions {
	options.Kpi = kpi
	return options
}

// SetHeaders : Allow user to set Headers
func (options *UpdateOccurrenceOptions) SetHeaders(param map[string]string) *UpdateOccurrenceOptions {
	options.Headers = param
	return options
}

// ValueType : the value type of a card element.
type ValueType struct {

	// Kind of element
	// - KPI&#58; Kind of value derived from a KPI occurrence
	// - FINDING_COUNT&#58; Kind of value derived from a count of finding occurrences.
	Kind *string `json:"kind" validate:"required"`

	// The text of this element type.
	Text *string `json:"text" validate:"required"`
}

// Constants associated with the ValueType.Kind property.
// Kind of element
// - KPI&#58; Kind of value derived from a KPI occurrence
// - FINDING_COUNT&#58; Kind of value derived from a count of finding occurrences.
const (
	ValueType_Kind_FindingCount = "FINDING_COUNT"
	ValueType_Kind_Kpi          = "KPI"
)

// NewValueType : Instantiate ValueType (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewValueType(kind string, text string) (model *ValueType, err error) {
	model = &ValueType{
		Kind: core.StringPtr(kind),
		Text: core.StringPtr(text),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// ApiListNoteOccurrencesResponse : Response including listed occurrences for a note.
type ApiListNoteOccurrencesResponse struct {

	// The occurrences attached to the specified note.
	Occurrences []ApiOccurrence `json:"occurrences,omitempty"`

	// Token to receive the next page of notes.
	NextPageToken *string `json:"next_page_token,omitempty"`
}

// ApiListNotesResponse : Response including listed notes.
type ApiListNotesResponse struct {
	Notes []ApiNote `json:"notes,omitempty"`

	// The next pagination token in the list response. It should be used as page_token for the following request. An empty
	// value means no more result.
	NextPageToken *string `json:"next_page_token,omitempty"`
}

// ApiListOccurrencesResponse : Response including listed active occurrences.
type ApiListOccurrencesResponse struct {

	// The occurrences requested.
	Occurrences []ApiOccurrence `json:"occurrences,omitempty"`

	// The next pagination token in the list response. It should be used as
	// `page_token` for the following request. An empty value means no more results.
	NextPageToken *string `json:"next_page_token,omitempty"`
}

// ApiListProvidersResponse : Response including listed providers.
type ApiListProvidersResponse struct {
	Providers []ApiProvider `json:"providers,omitempty"`
}

// ApiNote : Provides a detailed description of a `Note`.
type ApiNote struct {

	// A one sentence description of this `Note`.
	ShortDescription *string `json:"short_description" validate:"required"`

	// A detailed description of this `Note`.
	LongDescription *string `json:"long_description" validate:"required"`

	// Output only. This explicitly denotes which kind of note is specified. This
	// field can be used as a filter in list requests.
	Kind *string `json:"kind" validate:"required"`

	RelatedURL []ApiNoteRelatedURL `json:"related_url,omitempty"`

	// Time of expiration for this note, null if note does not expire.
	ExpirationTime *strfmt.DateTime `json:"expiration_time,omitempty"`

	// Output only. The time this note was created. This field can be used as a filter in list requests.
	CreateTime *strfmt.DateTime `json:"create_time,omitempty"`

	// Output only. The time this note was last updated. This field can be used as a filter in list requests.
	UpdateTime *strfmt.DateTime `json:"update_time,omitempty"`

	ID *string `json:"id" validate:"required"`

	// True if this `Note` can be shared by multiple accounts.
	Shared *bool `json:"shared,omitempty"`

	// Details about the reporter of this `Note`.
	ReportedBy *Reporter `json:"reported_by" validate:"required"`

	// The finding details of the note.
	Finding *FindingType `json:"finding,omitempty"`

	// The KPI details of the note.
	Kpi *KpiType `json:"kpi,omitempty"`

	// The card details of the note.
	Card *Card `json:"card,omitempty"`

	// The section details of the note.
	Section *Section `json:"section,omitempty"`
}

// NewApiNote : Instantiate ApiNote (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewApiNote(shortDescription string, longDescription string, kind string, ID string, reportedBy *Reporter) (model *ApiNote, err error) {
	model = &ApiNote{
		ShortDescription: core.StringPtr(shortDescription),
		LongDescription:  core.StringPtr(longDescription),
		Kind:             core.StringPtr(kind),
		ID:               core.StringPtr(ID),
		ReportedBy:       reportedBy,
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// ApiNoteKind : This must be 1&#58;1 with members of our oneofs, it can be used for filtering Note and Occurrence on their kind.
//  - FINDING&#58; The note and occurrence represent a finding.
//  - KPI&#58; The note and occurrence represent a KPI value.
//  - CARD&#58; The note represents a card showing findings and related metric values.
//  - CARD_CONFIGURED&#58; The note represents a card configured for a user account.
//  - SECTION&#58; The note represents a section in a dashboard.
type ApiNoteKind struct {
}

// ApiNoteRelatedURL : Metadata for any related URL information.
type ApiNoteRelatedURL struct {
	Label *string `json:"label,omitempty"`

	URL *string `json:"url,omitempty"`
}

// ApiOccurrence : `Occurrence` includes information about analysis occurrences for an image.
type ApiOccurrence struct {

	// The unique URL of the resource, image or the container, for which the `Occurrence` applies. For example,
	// https://gcr.io/provider/image@sha256:foo. This field can be used as a filter in list requests.
	ResourceURL *string `json:"resource_url,omitempty"`

	// An analysis note associated with this image, in the form "{account_id}/providers/{provider_id}/notes/{note_id}" This
	// field can be used as a filter in list requests.
	NoteName *string `json:"note_name" validate:"required"`

	// Output only. This explicitly denotes which of the `Occurrence` details are specified.
	// This field can be used as a filter in list requests.
	Kind *string `json:"kind" validate:"required"`

	Remediation *string `json:"remediation,omitempty"`

	// Output only. The time this `Occurrence` was created.
	CreateTime *strfmt.DateTime `json:"create_time,omitempty"`

	// Output only. The time this `Occurrence` was last updated.
	UpdateTime *strfmt.DateTime `json:"update_time,omitempty"`

	ID *string `json:"id" validate:"required"`

	//OccurrenceID of the occurrence
	OccurrenceID *string `json:"occurrence_id,omitempty"`

	//ProviderID of the occurrence
	ProviderID *string `json:"provider_id,omitempty"`

	//Name of the occurrence
	Name *string `json:"name,omitempty"`

	// Details about the context of this `Occurrence`.
	Context *Context `json:"context,omitempty"`

	// Details of the occurrence of a finding.
	Finding *Finding `json:"finding,omitempty"`

	// Details of the occurrence of a KPI.
	Kpi *Kpi `json:"kpi,omitempty"`
}

// NewApiOccurrence : Instantiate ApiOccurrence (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewApiOccurrence(noteName string, kind string, ID string) (model *ApiOccurrence, err error) {
	model = &ApiOccurrence{
		NoteName: core.StringPtr(noteName),
		Kind:     core.StringPtr(kind),
		ID:       core.StringPtr(ID),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// ApiProvider : Provides a detailed description of a `Provider`.
type ApiProvider struct {
	Name *string `json:"name" validate:"required"`

	ID *string `json:"id" validate:"required"`
}

// BreakdownCardElement : A card element with a breakdown of values.
type BreakdownCardElement struct {
	// The kind of this card element.
	Kind *string `json:"kind" validate:"required"`

	// The text of this card element.
	Text *string `json:"text" validate:"required"`

	// the value types associated to this card element.
	ValueTypes []ValueType `json:"value_types" validate:"required"`
}

// Constants associated with the BreakdownCardElement.Kind property.
// Kind of element
// - NUMERIC&#58; Single numeric value
// - BREAKDOWN&#58; Breakdown of numeric values
// - TIME_SERIES&#58; Time-series of numeric values.
const (
	BreakdownCardElement_Kind_Breakdown  = "BREAKDOWN"
	BreakdownCardElement_Kind_Numeric    = "NUMERIC"
	BreakdownCardElement_Kind_TimeSeries = "TIME_SERIES"
)

// NewBreakdownCardElement : Instantiate BreakdownCardElement (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewBreakdownCardElement(kind string, text string, valueTypes []ValueType) (model *BreakdownCardElement, err error) {
	model = &BreakdownCardElement{
		Kind:       core.StringPtr(kind),
		Text:       core.StringPtr(text),
		ValueTypes: valueTypes,
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// NumericCardElement : A card element with a single numeric value.
type NumericCardElement struct {
	// The kind of this card element.
	Kind *string `json:"kind" validate:"required"`

	// The text of this card element.
	Text *string `json:"text" validate:"required"`

	ValueType interface{} `json:"value_type" validate:"required"`
}

// Constants associated with the NumericCardElement.Kind property.
// Kind of element
// - NUMERIC&#58; Single numeric value
// - BREAKDOWN&#58; Breakdown of numeric values
// - TIME_SERIES&#58; Time-series of numeric values.
const (
	NumericCardElement_Kind_Breakdown  = "BREAKDOWN"
	NumericCardElement_Kind_Numeric    = "NUMERIC"
	NumericCardElement_Kind_TimeSeries = "TIME_SERIES"
)

// NewNumericCardElement : Instantiate NumericCardElement (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewNumericCardElement(kind string, text string, valueType interface{}) (model *NumericCardElement, err error) {
	model = &NumericCardElement{
		Kind:      core.StringPtr(kind),
		Text:      core.StringPtr(text),
		ValueType: valueType,
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// TimeSeriesCardElement : A card element with a time series chart.
type TimeSeriesCardElement struct {

	// The kind of this card element.
	Kind *string `json:"kind" validate:"required"`

	// The text of this card element.
	Text *string `json:"text" validate:"required"`

	// The default interval of the time series.
	DefaultInterval *string `json:"default_interval,omitempty"`

	// the value types associated to this card element.
	ValueTypes []FindingCountValueType `json:"value_types" validate:"required"`
}

// Constants associated with the TimeSeriesCardElement.Kind property.
// Kind of element
// - NUMERIC&#58; Single numeric value
// - BREAKDOWN&#58; Breakdown of numeric values
// - TIME_SERIES&#58; Time-series of numeric values.
const (
	TimeSeriesCardElement_Kind_Breakdown  = "BREAKDOWN"
	TimeSeriesCardElement_Kind_Numeric    = "NUMERIC"
	TimeSeriesCardElement_Kind_TimeSeries = "TIME_SERIES"
)

// NewTimeSeriesCardElement : Instantiate TimeSeriesCardElement (Generic Model Constructor)
func (findingsApi *FindingsApiV1) NewTimeSeriesCardElement(kind string, text string, valueTypes []FindingCountValueType) (model *TimeSeriesCardElement, err error) {
	model = &TimeSeriesCardElement{
		Kind:       core.StringPtr(kind),
		Text:       core.StringPtr(text),
		ValueTypes: valueTypes,
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}
