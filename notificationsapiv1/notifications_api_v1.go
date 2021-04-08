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

// Package notificationsapiv1 : Operations and models for the NotificationsApiV1 service
package notificationsapiv1

import (
	"fmt"

	"github.com/IBM/go-sdk-core/v3/core"
	common "github.com/ibm-cloud-security/security-advisor-sdk-go/v2/common"
)

// NotificationsApiV1 : notifications-api
//
// Version: 1.0.0
type NotificationsApiV1 struct {
	Service *core.BaseService
}

// DefaultServiceURL is the default URL to make service requests to.
const DefaultServiceURL = "https://us-south.secadvisor.cloud.ibm.com/notifications"

// DefaultServiceName is the default key used to find external configuration information.
const DefaultServiceName = "notifications_api"

// NotificationsApiV1Options : Service options
type NotificationsApiV1Options struct {
	ServiceName   string
	URL           string
	Authenticator core.Authenticator
}

// NewNotificationsApiV1UsingExternalConfig : constructs an instance of NotificationsApiV1 with passed in options and external configuration.
func NewNotificationsApiV1UsingExternalConfig(options *NotificationsApiV1Options) (notificationsApi *NotificationsApiV1, err error) {
	if options.ServiceName == "" {
		options.ServiceName = DefaultServiceName
	}

	if options.Authenticator == nil {
		options.Authenticator, err = core.GetAuthenticatorFromEnvironment(options.ServiceName)
		if err != nil {
			return
		}
	}

	notificationsApi, err = NewNotificationsApiV1(options)
	if err != nil {
		return
	}

	err = notificationsApi.Service.ConfigureService(options.ServiceName)
	if err != nil {
		return
	}

	if options.URL != "" {
		err = notificationsApi.Service.SetServiceURL(options.URL)
	}
	return
}

// NewNotificationsApiV1 : constructs an instance of NotificationsApiV1 with passed in options.
func NewNotificationsApiV1(options *NotificationsApiV1Options) (service *NotificationsApiV1, err error) {
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

	service = &NotificationsApiV1{
		Service: baseService,
	}

	return
}

// SetServiceURL sets the service URL
func (notificationsApi *NotificationsApiV1) SetServiceURL(url string) error {
	return notificationsApi.Service.SetServiceURL(url)
}

// ListAllChannels : list all channels
// list all channels under this account.
func (notificationsApi *NotificationsApiV1) ListAllChannels(listAllChannelsOptions *ListAllChannelsOptions) (result *ListChannelsResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(listAllChannelsOptions, "listAllChannelsOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(listAllChannelsOptions, "listAllChannelsOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "notifications/channels"}
	pathParameters := []string{*listAllChannelsOptions.AccountID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(notificationsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range listAllChannelsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("notifications_api", "V1", "ListAllChannels")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	if listAllChannelsOptions.Limit != nil {
		builder.AddQuery("limit", fmt.Sprint(*listAllChannelsOptions.Limit))
	}
	if listAllChannelsOptions.Skip != nil {
		builder.AddQuery("skip", fmt.Sprint(*listAllChannelsOptions.Skip))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = notificationsApi.Service.Request(request, new(ListChannelsResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*ListChannelsResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response")
		}
	}

	return
}

// CreateNotificationChannel : create notification channel
// create notification channel.
func (notificationsApi *NotificationsApiV1) CreateNotificationChannel(createNotificationChannelOptions *CreateNotificationChannelOptions) (result *CreateChannelsResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(createNotificationChannelOptions, "createNotificationChannelOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(createNotificationChannelOptions, "createNotificationChannelOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "notifications/channels"}
	pathParameters := []string{*createNotificationChannelOptions.AccountID}

	builder := core.NewRequestBuilder(core.POST)
	_, err = builder.ConstructHTTPURL(notificationsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range createNotificationChannelOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("notifications_api", "V1", "CreateNotificationChannel")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if createNotificationChannelOptions.Name != nil {
		body["name"] = createNotificationChannelOptions.Name
	}
	if createNotificationChannelOptions.Type != nil {
		body["type"] = createNotificationChannelOptions.Type
	}
	if createNotificationChannelOptions.Endpoint != nil {
		body["endpoint"] = createNotificationChannelOptions.Endpoint
	}
	if createNotificationChannelOptions.Description != nil {
		body["description"] = createNotificationChannelOptions.Description
	}
	if createNotificationChannelOptions.Severity != nil {
		body["severity"] = createNotificationChannelOptions.Severity
	}
	if createNotificationChannelOptions.Enabled != nil {
		body["enabled"] = createNotificationChannelOptions.Enabled
	}
	if createNotificationChannelOptions.AlertSource != nil {
		body["alert_source"] = createNotificationChannelOptions.AlertSource
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = notificationsApi.Service.Request(request, new(CreateChannelsResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*CreateChannelsResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// DeleteNotificationChannels : bulk delete of channels
// bulk delete of channels.
func (notificationsApi *NotificationsApiV1) DeleteNotificationChannels(deleteNotificationChannelsOptions *DeleteNotificationChannelsOptions) (result *BulkDeleteChannelsResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(deleteNotificationChannelsOptions, "deleteNotificationChannelsOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(deleteNotificationChannelsOptions, "deleteNotificationChannelsOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "notifications/channels"}
	pathParameters := []string{*deleteNotificationChannelsOptions.AccountID}

	builder := core.NewRequestBuilder(core.DELETE)
	_, err = builder.ConstructHTTPURL(notificationsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range deleteNotificationChannelsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("notifications_api", "V1", "DeleteNotificationChannels")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	_, err = builder.SetBodyContentJSON(deleteNotificationChannelsOptions.Body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = notificationsApi.Service.Request(request, new(BulkDeleteChannelsResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*BulkDeleteChannelsResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// DeleteNotificationChannel : delete the details of a specific channel
// delete the details of a specific channel.
func (notificationsApi *NotificationsApiV1) DeleteNotificationChannel(deleteNotificationChannelOptions *DeleteNotificationChannelOptions) (result *DeleteChannelResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(deleteNotificationChannelOptions, "deleteNotificationChannelOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(deleteNotificationChannelOptions, "deleteNotificationChannelOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "notifications/channels"}
	pathParameters := []string{*deleteNotificationChannelOptions.AccountID, *deleteNotificationChannelOptions.ChannelID}

	builder := core.NewRequestBuilder(core.DELETE)
	_, err = builder.ConstructHTTPURL(notificationsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range deleteNotificationChannelOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("notifications_api", "V1", "DeleteNotificationChannel")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = notificationsApi.Service.Request(request, new(DeleteChannelResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*DeleteChannelResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// GetNotificationChannel : get the details of a specific channel
// get the details of a specific channel.
func (notificationsApi *NotificationsApiV1) GetNotificationChannel(getNotificationChannelOptions *GetNotificationChannelOptions) (result *GetChannelResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getNotificationChannelOptions, "getNotificationChannelOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getNotificationChannelOptions, "getNotificationChannelOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "notifications/channels"}
	pathParameters := []string{*getNotificationChannelOptions.AccountID, *getNotificationChannelOptions.ChannelID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(notificationsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range getNotificationChannelOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("notifications_api", "V1", "GetNotificationChannel")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = notificationsApi.Service.Request(request, new(GetChannelResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*GetChannelResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// UpdateNotificationChannel : update notification channel
// update notification channel.
func (notificationsApi *NotificationsApiV1) UpdateNotificationChannel(updateNotificationChannelOptions *UpdateNotificationChannelOptions) (result *UpdateChannelResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(updateNotificationChannelOptions, "updateNotificationChannelOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(updateNotificationChannelOptions, "updateNotificationChannelOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "notifications/channels"}
	pathParameters := []string{*updateNotificationChannelOptions.AccountID, *updateNotificationChannelOptions.ChannelID}

	builder := core.NewRequestBuilder(core.PUT)
	_, err = builder.ConstructHTTPURL(notificationsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range updateNotificationChannelOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("notifications_api", "V1", "UpdateNotificationChannel")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")

	body := make(map[string]interface{})
	if updateNotificationChannelOptions.Name != nil {
		body["name"] = updateNotificationChannelOptions.Name
	}
	if updateNotificationChannelOptions.Type != nil {
		body["type"] = updateNotificationChannelOptions.Type
	}
	if updateNotificationChannelOptions.Endpoint != nil {
		body["endpoint"] = updateNotificationChannelOptions.Endpoint
	}
	if updateNotificationChannelOptions.Description != nil {
		body["description"] = updateNotificationChannelOptions.Description
	}
	if updateNotificationChannelOptions.Severity != nil {
		body["severity"] = updateNotificationChannelOptions.Severity
	}
	if updateNotificationChannelOptions.Enabled != nil {
		body["enabled"] = updateNotificationChannelOptions.Enabled
	}
	if updateNotificationChannelOptions.AlertSource != nil {
		body["alert_source"] = updateNotificationChannelOptions.AlertSource
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = notificationsApi.Service.Request(request, new(UpdateChannelResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*UpdateChannelResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// TestNotificationChannel : test notification channel
// test a nofication channel under this account.
func (notificationsApi *NotificationsApiV1) TestNotificationChannel(testNotificationChannelOptions *TestNotificationChannelOptions) (result *TestChannelResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(testNotificationChannelOptions, "testNotificationChannelOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(testNotificationChannelOptions, "testNotificationChannelOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "notifications/channels", "test"}
	pathParameters := []string{*testNotificationChannelOptions.AccountID, *testNotificationChannelOptions.ChannelID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(notificationsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range testNotificationChannelOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("notifications_api", "V1", "TestNotificationChannel")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = notificationsApi.Service.Request(request, new(TestChannelResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*TestChannelResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// GetPublicKey : fetch notifications public key
// fetch public key to decrypt messages in notification payload.
func (notificationsApi *NotificationsApiV1) GetPublicKey(getPublicKeyOptions *GetPublicKeyOptions) (result *PublicKeyResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(getPublicKeyOptions, "getPublicKeyOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(getPublicKeyOptions, "getPublicKeyOptions")
	if err != nil {
		return
	}

	pathSegments := []string{"v1", "notifications/public_key"}
	pathParameters := []string{*getPublicKeyOptions.AccountID}

	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ConstructHTTPURL(notificationsApi.Service.Options.URL, pathSegments, pathParameters)
	if err != nil {
		return
	}

	for headerName, headerValue := range getPublicKeyOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("notifications_api", "V1", "GetPublicKey")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	builder.AddHeader("Accept", "application/json")

	request, err := builder.Build()
	if err != nil {
		return
	}

	response, err = notificationsApi.Service.Request(request, new(PublicKeyResponse))
	if err == nil {
		var ok bool
		result, ok = response.Result.(*PublicKeyResponse)
		if !ok {
			err = fmt.Errorf("An error occurred while processing the operation response.")
		}
	}

	return
}

// ChannelResponseDefinitionAlertSourceItem : The alert sources. They identify the providers and their finding types which makes the findings available to Security
// Advisor.
type ChannelResponseDefinitionAlertSourceItem struct {

	// Below is a list of builtin providers that you can select in addition to the ones you obtain by calling Findings API
	// /v1/{account_id}/providers :
	//  | provider_name | The source they represent |
	//  |-----|-----|
	//  | VA  | Vulnerable image findings|
	//  | NA  | Network Insights findings|
	//  | ATA | Activity Insights findings|
	//  | CERT | Certificate Manager findings|
	//  | ALL | Special provider name to represent all the providers. Its mutually exclusive with other providers meaning
	// either you choose ALL or you don't|.
	ProviderName *string `json:"provider_name,omitempty"`

	// An array of the finding types of the provider_name or "ALL" to specify all finding types under that provider Below
	// is a list of supported finding types for each built in providers
	// | provider_name | Supported finding types |
	// |-----|-----|
	// | VA  | "image_with_vulnerabilities", "image_with_config_issues"|
	// | NA  | "anonym_server", "malware_server", "bot_server", "miner_server", "server_suspected_ratio",
	// "server_response", "data_extrusion", "server_weaponized_total"|
	// | ATA | "appid", "cos", "iks", "iam", "kms", "cert", "account", "app"|
	// | CERT | "expired_cert", "expiring_1day_cert", "expiring_10day_cert", "expiring_30day_cert", "expiring_60day_cert",
	// "expiring_90day_cert"|
	// | config-advisor | "appprotection-dns_not_proxied", "appprotection-dnssec_off", "appprotection-ssl_not_strict",
	// "appprotection-tls_min_version", "appprotection-waf_off", "appprotection-waf_rules", "calico-deny_all_rule",
	// "calico-nonstandard_ports", "calico-update_cis_whitelist", "datacos-cos_managers", "datacos-not_encrypted_via_kp",
	// "datacos-not_in_private_network", "datacos-public_bucket_acl", "datacos-public_bucket_iam",
	// "datacos-public_object_acl", "iam-account_admins", "iam-all_resource_managers", "iam-all_resource_readers",
	// "iam-identity_admins", "iam-kms_managers", "iam-out_of_group"|
	// | ALL | "ALL"|.
	FindingTypes []string `json:"finding_types,omitempty"`
}

// ChannelResponseDefinitionSeverity : Severity of the notification.
type ChannelResponseDefinitionSeverity struct {

	// Critical Severity.
	Critical *bool `json:"critical,omitempty"`

	// High Severity.
	High *bool `json:"high,omitempty"`

	// Medium Severity.
	Medium *bool `json:"medium,omitempty"`

	// Low Severity.
	Low *bool `json:"low,omitempty"`
}

// CreateNotificationChannelOptions : The CreateNotificationChannel options.
type CreateNotificationChannelOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"omitempty"`

	Name *string `json:"name" validate:"required"`

	// Type of callback URL.
	Type *string `json:"type" validate:"required"`

	// The callback URL which receives the notification.
	Endpoint *string `json:"endpoint" validate:"required"`

	// A one sentence description of this `Channel`.
	Description *string `json:"description,omitempty"`

	// Severity of the notification to be received.
	Severity []string `json:"severity,omitempty"`

	// Channel is enabled or not. Default is disabled.
	Enabled *bool `json:"enabled,omitempty"`

	AlertSource []NotificationChannelAlertSourceItem `json:"alert_source,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// Constants associated with the CreateNotificationChannelOptions.Type property.
// Type of callback URL.
const (
	CreateNotificationChannelOptions_Type_Webhook = "Webhook"
)

// Constants associated with the CreateNotificationChannelOptions.Severity property.
const (
	CreateNotificationChannelOptions_Severity_Critical = "critical"
	CreateNotificationChannelOptions_Severity_High     = "high"
	CreateNotificationChannelOptions_Severity_Low      = "low"
	CreateNotificationChannelOptions_Severity_Medium   = "medium"
)

// NewCreateNotificationChannelOptions : Instantiate CreateNotificationChannelOptions
func (notificationsApi *NotificationsApiV1) NewCreateNotificationChannelOptions(accountID string, name string, typeVar string, endpoint string) *CreateNotificationChannelOptions {
	return &CreateNotificationChannelOptions{
		AccountID: core.StringPtr(accountID),
		Name:      core.StringPtr(name),
		Type:      core.StringPtr(typeVar),
		Endpoint:  core.StringPtr(endpoint),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *CreateNotificationChannelOptions) SetAccountID(accountID string) *CreateNotificationChannelOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetName : Allow user to set Name
func (options *CreateNotificationChannelOptions) SetName(name string) *CreateNotificationChannelOptions {
	options.Name = core.StringPtr(name)
	return options
}

// SetType : Allow user to set Type
func (options *CreateNotificationChannelOptions) SetType(typeVar string) *CreateNotificationChannelOptions {
	options.Type = core.StringPtr(typeVar)
	return options
}

// SetEndpoint : Allow user to set Endpoint
func (options *CreateNotificationChannelOptions) SetEndpoint(endpoint string) *CreateNotificationChannelOptions {
	options.Endpoint = core.StringPtr(endpoint)
	return options
}

// SetDescription : Allow user to set Description
func (options *CreateNotificationChannelOptions) SetDescription(description string) *CreateNotificationChannelOptions {
	options.Description = core.StringPtr(description)
	return options
}

// SetSeverity : Allow user to set Severity
func (options *CreateNotificationChannelOptions) SetSeverity(severity []string) *CreateNotificationChannelOptions {
	options.Severity = severity
	return options
}

// SetEnabled : Allow user to set Enabled
func (options *CreateNotificationChannelOptions) SetEnabled(enabled bool) *CreateNotificationChannelOptions {
	options.Enabled = core.BoolPtr(enabled)
	return options
}

// SetAlertSource : Allow user to set AlertSource
func (options *CreateNotificationChannelOptions) SetAlertSource(alertSource []NotificationChannelAlertSourceItem) *CreateNotificationChannelOptions {
	options.AlertSource = alertSource
	return options
}

// SetHeaders : Allow user to set Headers
func (options *CreateNotificationChannelOptions) SetHeaders(param map[string]string) *CreateNotificationChannelOptions {
	options.Headers = param
	return options
}

// DeleteNotificationChannelOptions : The DeleteNotificationChannel options.
type DeleteNotificationChannelOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Channel ID.
	ChannelID *string `json:"channel_id" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewDeleteNotificationChannelOptions : Instantiate DeleteNotificationChannelOptions
func (notificationsApi *NotificationsApiV1) NewDeleteNotificationChannelOptions(accountID string, channelID string) *DeleteNotificationChannelOptions {
	return &DeleteNotificationChannelOptions{
		AccountID: core.StringPtr(accountID),
		ChannelID: core.StringPtr(channelID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *DeleteNotificationChannelOptions) SetAccountID(accountID string) *DeleteNotificationChannelOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetChannelID : Allow user to set ChannelID
func (options *DeleteNotificationChannelOptions) SetChannelID(channelID string) *DeleteNotificationChannelOptions {
	options.ChannelID = core.StringPtr(channelID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteNotificationChannelOptions) SetHeaders(param map[string]string) *DeleteNotificationChannelOptions {
	options.Headers = param
	return options
}

// DeleteNotificationChannelsOptions : The DeleteNotificationChannels options.
type DeleteNotificationChannelsOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Body for bulk delete notification channels.
	Body []string `json:"body" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewDeleteNotificationChannelsOptions : Instantiate DeleteNotificationChannelsOptions
func (notificationsApi *NotificationsApiV1) NewDeleteNotificationChannelsOptions(accountID string, body []string) *DeleteNotificationChannelsOptions {
	return &DeleteNotificationChannelsOptions{
		AccountID: core.StringPtr(accountID),
		Body:      body,
	}
}

// SetAccountID : Allow user to set AccountID
func (options *DeleteNotificationChannelsOptions) SetAccountID(accountID string) *DeleteNotificationChannelsOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetBody : Allow user to set Body
func (options *DeleteNotificationChannelsOptions) SetBody(body []string) *DeleteNotificationChannelsOptions {
	options.Body = body
	return options
}

// SetHeaders : Allow user to set Headers
func (options *DeleteNotificationChannelsOptions) SetHeaders(param map[string]string) *DeleteNotificationChannelsOptions {
	options.Headers = param
	return options
}

// GetNotificationChannelOptions : The GetNotificationChannel options.
type GetNotificationChannelOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Channel ID.
	ChannelID *string `json:"channel_id" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetNotificationChannelOptions : Instantiate GetNotificationChannelOptions
func (notificationsApi *NotificationsApiV1) NewGetNotificationChannelOptions(accountID string, channelID string) *GetNotificationChannelOptions {
	return &GetNotificationChannelOptions{
		AccountID: core.StringPtr(accountID),
		ChannelID: core.StringPtr(channelID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *GetNotificationChannelOptions) SetAccountID(accountID string) *GetNotificationChannelOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetChannelID : Allow user to set ChannelID
func (options *GetNotificationChannelOptions) SetChannelID(channelID string) *GetNotificationChannelOptions {
	options.ChannelID = core.StringPtr(channelID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetNotificationChannelOptions) SetHeaders(param map[string]string) *GetNotificationChannelOptions {
	options.Headers = param
	return options
}

// GetPublicKeyOptions : The GetPublicKey options.
type GetPublicKeyOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewGetPublicKeyOptions : Instantiate GetPublicKeyOptions
func (notificationsApi *NotificationsApiV1) NewGetPublicKeyOptions(accountID string) *GetPublicKeyOptions {
	return &GetPublicKeyOptions{
		AccountID: core.StringPtr(accountID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *GetPublicKeyOptions) SetAccountID(accountID string) *GetPublicKeyOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *GetPublicKeyOptions) SetHeaders(param map[string]string) *GetPublicKeyOptions {
	options.Headers = param
	return options
}

// ListAllChannelsOptions : The ListAllChannels options.
type ListAllChannelsOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Limit the number of the returned documents to the specified number.
	Limit *int64 `json:"limit,omitempty"`

	// The offset is the index of the item from which you want to start returning data from. Default is 0.
	Skip *int64 `json:"skip,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewListAllChannelsOptions : Instantiate ListAllChannelsOptions
func (notificationsApi *NotificationsApiV1) NewListAllChannelsOptions(accountID string) *ListAllChannelsOptions {
	return &ListAllChannelsOptions{
		AccountID: core.StringPtr(accountID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *ListAllChannelsOptions) SetAccountID(accountID string) *ListAllChannelsOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetLimit : Allow user to set Limit
func (options *ListAllChannelsOptions) SetLimit(limit int64) *ListAllChannelsOptions {
	options.Limit = core.Int64Ptr(limit)
	return options
}

// SetSkip : Allow user to set Skip
func (options *ListAllChannelsOptions) SetSkip(skip int64) *ListAllChannelsOptions {
	options.Skip = core.Int64Ptr(skip)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *ListAllChannelsOptions) SetHeaders(param map[string]string) *ListAllChannelsOptions {
	options.Headers = param
	return options
}

// NotificationChannelAlertSourceItem : The alert sources. They identify the providers and their finding types which makes the findings available to Security
// Advisor.
type NotificationChannelAlertSourceItem struct {

	// Below is a list of builtin providers that you can select in addition to the ones you obtain by calling Findings API
	// /v1/{account_id}/providers :
	//  | provider_name | The source they represent |
	//  |-----|-----|
	//  | VA  | Vulnerable image findings|
	//  | NA  | Network Insights findings|
	//  | ATA | Activity Insights findings|
	//  | CERT | Certificate Manager findings|
	//  | ALL | Special provider name to represent all the providers. Its mutually exclusive with other providers meaning
	// either you choose ALL or you don't|.
	ProviderName *string `json:"provider_name" validate:"required"`

	// An array of the finding types of the provider_name or "ALL" to specify all finding types under that provider Below
	// is a list of supported finding types for each built in providers
	// | provider_name | Supported finding types |
	// |-----|-----|
	// | VA  | "image_with_vulnerabilities", "image_with_config_issues"|
	// | NA  | "anonym_server", "malware_server", "bot_server", "miner_server", "server_suspected_ratio",
	// "server_response", "data_extrusion", "server_weaponized_total"|
	// | ATA | "appid", "cos", "iks", "iam", "kms", "cert", "account", "app"|
	// | CERT | "expired_cert", "expiring_1day_cert", "expiring_10day_cert", "expiring_30day_cert", "expiring_60day_cert",
	// "expiring_90day_cert"|
	// | config-advisor | "appprotection-dns_not_proxied", "appprotection-dnssec_off", "appprotection-ssl_not_strict",
	// "appprotection-tls_min_version", "appprotection-waf_off", "appprotection-waf_rules", "calico-deny_all_rule",
	// "calico-nonstandard_ports", "calico-update_cis_whitelist", "datacos-cos_managers", "datacos-not_encrypted_via_kp",
	// "datacos-not_in_private_network", "datacos-public_bucket_acl", "datacos-public_bucket_iam",
	// "datacos-public_object_acl", "iam-account_admins", "iam-all_resource_managers", "iam-all_resource_readers",
	// "iam-identity_admins", "iam-kms_managers", "iam-out_of_group"|
	// | ALL | "ALL"|.
	FindingTypes []string `json:"finding_types,omitempty"`
}

// NewNotificationChannelAlertSourceItem : Instantiate NotificationChannelAlertSourceItem (Generic Model Constructor)
func (notificationsApi *NotificationsApiV1) NewNotificationChannelAlertSourceItem(providerName string) (model *NotificationChannelAlertSourceItem, err error) {
	model = &NotificationChannelAlertSourceItem{
		ProviderName: core.StringPtr(providerName),
	}
	err = core.ValidateStruct(model, "required parameters")
	return
}

// TestNotificationChannelOptions : The TestNotificationChannel options.
type TestNotificationChannelOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Channel ID.
	ChannelID *string `json:"channel_id" validate:"required"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// NewTestNotificationChannelOptions : Instantiate TestNotificationChannelOptions
func (notificationsApi *NotificationsApiV1) NewTestNotificationChannelOptions(accountID string, channelID string) *TestNotificationChannelOptions {
	return &TestNotificationChannelOptions{
		AccountID: core.StringPtr(accountID),
		ChannelID: core.StringPtr(channelID),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *TestNotificationChannelOptions) SetAccountID(accountID string) *TestNotificationChannelOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetChannelID : Allow user to set ChannelID
func (options *TestNotificationChannelOptions) SetChannelID(channelID string) *TestNotificationChannelOptions {
	options.ChannelID = core.StringPtr(channelID)
	return options
}

// SetHeaders : Allow user to set Headers
func (options *TestNotificationChannelOptions) SetHeaders(param map[string]string) *TestNotificationChannelOptions {
	options.Headers = param
	return options
}

// UpdateNotificationChannelOptions : The UpdateNotificationChannel options.
type UpdateNotificationChannelOptions struct {

	// Account ID.
	AccountID *string `json:"account_id" validate:"required"`

	// Channel ID.
	ChannelID *string `json:"channel_id" validate:"required"`

	Name *string `json:"name" validate:"required"`

	// Type of callback URL.
	Type *string `json:"type" validate:"required"`

	// The callback URL which receives the notification.
	Endpoint *string `json:"endpoint" validate:"required"`

	// A one sentence description of this `Channel`.
	Description *string `json:"description,omitempty"`

	// Severity of the notification to be received.
	Severity []string `json:"severity,omitempty"`

	// Channel is enabled or not. Default is disabled.
	Enabled *bool `json:"enabled,omitempty"`

	AlertSource []NotificationChannelAlertSourceItem `json:"alert_source,omitempty"`

	// Allows users to set headers to be GDPR compliant
	Headers map[string]string
}

// Constants associated with the UpdateNotificationChannelOptions.Type property.
// Type of callback URL.
const (
	UpdateNotificationChannelOptions_Type_Webhook = "Webhook"
)

// Constants associated with the UpdateNotificationChannelOptions.Severity property.
const (
	UpdateNotificationChannelOptions_Severity_Critical = "critical"
	UpdateNotificationChannelOptions_Severity_High     = "high"
	UpdateNotificationChannelOptions_Severity_Low      = "low"
	UpdateNotificationChannelOptions_Severity_Medium   = "medium"
)

// NewUpdateNotificationChannelOptions : Instantiate UpdateNotificationChannelOptions
func (notificationsApi *NotificationsApiV1) NewUpdateNotificationChannelOptions(accountID string, channelID string, name string, typeVar string, endpoint string) *UpdateNotificationChannelOptions {
	return &UpdateNotificationChannelOptions{
		AccountID: core.StringPtr(accountID),
		ChannelID: core.StringPtr(channelID),
		Name:      core.StringPtr(name),
		Type:      core.StringPtr(typeVar),
		Endpoint:  core.StringPtr(endpoint),
	}
}

// SetAccountID : Allow user to set AccountID
func (options *UpdateNotificationChannelOptions) SetAccountID(accountID string) *UpdateNotificationChannelOptions {
	options.AccountID = core.StringPtr(accountID)
	return options
}

// SetChannelID : Allow user to set ChannelID
func (options *UpdateNotificationChannelOptions) SetChannelID(channelID string) *UpdateNotificationChannelOptions {
	options.ChannelID = core.StringPtr(channelID)
	return options
}

// SetName : Allow user to set Name
func (options *UpdateNotificationChannelOptions) SetName(name string) *UpdateNotificationChannelOptions {
	options.Name = core.StringPtr(name)
	return options
}

// SetType : Allow user to set Type
func (options *UpdateNotificationChannelOptions) SetType(typeVar string) *UpdateNotificationChannelOptions {
	options.Type = core.StringPtr(typeVar)
	return options
}

// SetEndpoint : Allow user to set Endpoint
func (options *UpdateNotificationChannelOptions) SetEndpoint(endpoint string) *UpdateNotificationChannelOptions {
	options.Endpoint = core.StringPtr(endpoint)
	return options
}

// SetDescription : Allow user to set Description
func (options *UpdateNotificationChannelOptions) SetDescription(description string) *UpdateNotificationChannelOptions {
	options.Description = core.StringPtr(description)
	return options
}

// SetSeverity : Allow user to set Severity
func (options *UpdateNotificationChannelOptions) SetSeverity(severity []string) *UpdateNotificationChannelOptions {
	options.Severity = severity
	return options
}

// SetEnabled : Allow user to set Enabled
func (options *UpdateNotificationChannelOptions) SetEnabled(enabled bool) *UpdateNotificationChannelOptions {
	options.Enabled = core.BoolPtr(enabled)
	return options
}

// SetAlertSource : Allow user to set AlertSource
func (options *UpdateNotificationChannelOptions) SetAlertSource(alertSource []NotificationChannelAlertSourceItem) *UpdateNotificationChannelOptions {
	options.AlertSource = alertSource
	return options
}

// SetHeaders : Allow user to set Headers
func (options *UpdateNotificationChannelOptions) SetHeaders(param map[string]string) *UpdateNotificationChannelOptions {
	options.Headers = param
	return options
}

// BulkDeleteChannelsResponse : Response of all deleted channels.
type BulkDeleteChannelsResponse struct {

	// response message.
	Message *string `json:"message,omitempty"`
}

// ChannelResponseDefinition : Response including channels.
type ChannelResponseDefinition struct {

	// unique id of the channel.
	ChannelID *string `json:"channel_id,omitempty"`

	Name *string `json:"name,omitempty"`

	// A one sentence description of this `Channel`.
	Description *string `json:"description,omitempty"`

	// Type of callback URL.
	Type *string `json:"type,omitempty"`

	// Severity of the notification.
	Severity *ChannelResponseDefinitionSeverity `json:"severity,omitempty"`

	// The callback URL which receives the notification.
	Endpoint *string `json:"endpoint,omitempty"`

	// Channel is enabled or not. Default is disabled.
	Enabled *bool `json:"enabled,omitempty"`

	AlertSource []ChannelResponseDefinitionAlertSourceItem `json:"alert_source,omitempty"`

	Frequency *string `json:"frequency,omitempty"`
}

// Constants associated with the ChannelResponseDefinition.Type property.
// Type of callback URL.
const (
	ChannelResponseDefinition_Type_Webhook = "Webhook"
)

// CreateChannelsResponse : Response of created channel.
type CreateChannelsResponse struct {

	// id of the created channel.
	ChannelID *string `json:"channel_id,omitempty"`

	// response code.
	StatusCode *int64 `json:"status_code,omitempty"`
}

// DeleteChannelResponse : Response of deleted channel.
type DeleteChannelResponse struct {

	// id of the created channel.
	ChannelID *string `json:"channel_id,omitempty"`

	// response message.
	Message *string `json:"message,omitempty"`
}

// GetChannelResponse : Response of get channel.
type GetChannelResponse struct {

	// Response including channels.
	Channel *ChannelResponseDefinition `json:"channel,omitempty"`
}

// ListChannelsResponse : Response including channels.
type ListChannelsResponse struct {
	Channels []ChannelResponseDefinition `json:"channels,omitempty"`
}

// PublicKeyResponse : PublicKeyResponse struct
type PublicKeyResponse struct {
	PublicKey *string `json:"public_key" validate:"required"`
}

// TestChannelResponse : Response of deleted channel.
type TestChannelResponse struct {

	// response status.
	Test *string `json:"test,omitempty"`
}

// UpdateChannelResponse : Response of updated channel.
type UpdateChannelResponse struct {

	// id of the updated channel.
	ChannelID *string `json:"channel_id,omitempty"`

	// response code.
	StatusCode *int64 `json:"status_code,omitempty"`
}
