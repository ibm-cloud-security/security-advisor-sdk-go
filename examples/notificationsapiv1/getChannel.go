package examples

import (
	"fmt"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/ibm-cloud-security/security-advisor-sdk-go/v3/notificationsapiv1"
)

//GetChannel gets a channel
func GetChannel() {
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

	channelID := "6bb5f7b0-a1a7-11eb-a800-4b593bbe7d0c"

	getChannelOptions := service.NewGetNotificationChannelOptions(accountID, channelID)
	result, resp, operationErr := service.GetNotificationChannel(getChannelOptions)
	if operationErr != nil {
		fmt.Println(resp.Result)
		fmt.Println("Failed to get channel: ", operationErr)
		return
	}

	fmt.Println(*result.Channel.ChannelID)
	fmt.Println(*result.Channel.Name)
}
