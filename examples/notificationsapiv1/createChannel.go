package examples

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/ibm-cloud-security/security-advisor-sdk-go/v3/notificationsapiv1"
)

//CreateChannel creates a new channel
func CreateChannel() {
	headers := make(map[string]string)
	headers["Content-Type"] = "application/json"
	authenticator := &core.IamAuthenticator{
		ApiKey: apiKey,
		URL:    url, //use for dev/preprod env
	}
	service, _ := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
		Authenticator: authenticator,
		URL:           "https://us-south.secadvisor.cloud.ibm.com/notifications", //Specify url or use default
	})

	channelName := "sdktest_channel_exmpl1"
	endpoint := "https://ss.ss"
	channelType := "Webhook"
	severity := []string{notificationsapiv1.CreateNotificationChannelOptions_Severity_Low, notificationsapiv1.CreateNotificationChannelOptions_Severity_High, notificationsapiv1.CreateNotificationChannelOptions_Severity_Critical}

	var alertSource []notificationsapiv1.NotificationChannelAlertSourceItem
	source, _ := service.NewNotificationChannelAlertSourceItem("ATA")
	source.FindingTypes = []string{"appid", "cos", "iks"}
	alertSource = append(alertSource, *source)

	createOptions := service.NewCreateNotificationChannelOptions(accountID, channelName, channelType, endpoint)

	//Below set of calls are not required. A channel can be created with just channelName, channelType, endpoint. Rest will saaume default value.
	createOptions.SetHeaders(headers)
	createOptions.SetSeverity(severity)
	createOptions.SetEnabled(true)
	createOptions.SetDescription("this is a test")
	createOptions.SetAlertSource(alertSource)

	result, response, err := service.CreateNotificationChannel(createOptions)
	if err != nil {
		fmt.Println(response.Result)
		fmt.Println("Failed to create channel: ", err)
		return
	}
	fmt.Println(*result.ChannelID)
	fmt.Println(*result.StatusCode)

}

//CreateChannelUsingFile creates a new channel using data from a file
func CreateChannelUsingFile() {
	headers := make(map[string]string)
	headers["Content-Type"] = "application/json"
	authenticator := &core.IamAuthenticator{
		ApiKey: apiKey,
		URL:    url, //use for dev/preprod env
	}
	service, _ := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
		Authenticator: authenticator,
		URL:           "https://dev-dallas.secadvisor.test.cloud.ibm.com/notifications", //Specify url or use default
	})

	query, err := ioutil.ReadFile("./examples/input/channel_with_all.json")
	if err != nil {
		fmt.Println("Failed to open file: ", err)
		return
	}
	var createNotificationChannelOptions *notificationsapiv1.CreateNotificationChannelOptions
	json.Unmarshal([]byte(query), &createNotificationChannelOptions)
	createNotificationChannelOptions.SetHeaders(headers)

	result, resp, operationErr := service.CreateNotificationChannel(createNotificationChannelOptions)
	if operationErr != nil && resp.StatusCode != 200 {
		fmt.Println(resp.Result)
		fmt.Println("Failed to create channel: ", operationErr)
		return
	}

	fmt.Println(*result.ChannelID)
	fmt.Println(*result.StatusCode)

}
