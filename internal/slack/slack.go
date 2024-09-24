package slack

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

var api *slack.Client
var channelID string

type Config struct {
	Token     string
	ChannelId string
}

func Init(config Config) {
	token := config.Token
	channelID = config.ChannelId
	api = slack.New(token)

	log.Info().Msg("slack client initialized")
}

func PostMessage(text string) error {

	// attachment := slack.Attachment{
	// 	Title:   ":round_pushpin: Knock-knock",
	// 	Pretext: text,
	// 	// Text:    text,
	// 	// Uncomment the following part to send a field too
	// 	// Fields: []slack.AttachmentField{
	// 	// 	slack.AttachmentField{
	// 	// 		Title: "a",
	// 	// 		Value: "no",
	// 	// 	},
	// 	// },
	// }

	// Ref.: https://github.com/slack-go/slack/blob/master/examples/messages/messages.go

	msg := fmt.Sprintf(":mega: *Knock-knock* - %s", text)

	channelID, timestamp, err := api.PostMessage(
		channelID,
		slack.MsgOptionText(msg, false),
		// slack.MsgOptionAttachments(attachment),
		slack.MsgOptionAsUser(true), // Add this if you want that the bot would post message as a user, otherwise it will send response using the default slackbot
	)

	if err != nil {
		log.Error().Err(err).Msg("")
		return err
	}

	log.Debug().Msgf("Message successfully sent to channel %s at %s", channelID, timestamp)
	return nil
}
