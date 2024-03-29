package examples

import (
	"fmt"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/ibm-cloud-security/security-advisor-sdk-go/v3/notificationsapiv1"
)

//ListChannels lists all channel in an account
func ListChannels() {
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

	listChannelOptions := service.NewListAllChannelsOptions(accountID)

	//Use limit and skip to apply paging
	// listChannelOptions.SetLimit(5)
	// listChannelOptions.SetSkip(1)

	result, resp, operationErr := service.ListAllChannels(listChannelOptions)
	if operationErr != nil {
		fmt.Println(resp.Result)
		fmt.Println("Failed to get channel: ", operationErr)
		return
	}

	fmt.Println(*result.Channels[0].ChannelID)
	fmt.Println(*result.Channels[1].ChannelID)
	fmt.Println("Total Channels: ", len(result.Channels))

}
