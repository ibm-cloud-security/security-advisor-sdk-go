package examples

import (
	"fmt"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/ibm-cloud-security/security-advisor-sdk-go/v3/notificationsapiv1"
)

//TestConnection tests the connection to the endpoint of a channel
func TestConnection() {
	authenticator := &core.IamAuthenticator{
		ApiKey: apiKey,
		URL:    url, //use for dev/preprod env
	}
	service, _ := notificationsapiv1.NewNotificationsApiV1(&notificationsapiv1.NotificationsApiV1Options{
		Authenticator: authenticator,
		URL:           "https://us-south.secadvisor.cloud.ibm.com/notifications", //Specify url or use default
	})

	channelID := "f28ffd20-8ebc-11ea-b6bb-77a55a4ff9b0"

	testChannelOptions := service.NewTestNotificationChannelOptions(accountID, channelID)
	testResult, resp, operationErr := service.TestNotificationChannel(testChannelOptions)
	if operationErr != nil {
		fmt.Println(resp.Result)
		fmt.Println("Failed to test connection: ", operationErr)
		return
	}

	fmt.Println(*testResult.Test)
}
