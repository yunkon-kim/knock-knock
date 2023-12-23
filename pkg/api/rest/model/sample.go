package model

type MyUser struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type BasicResponse struct {
	Result string  `json:"Result"`
	Error  *string `json:"Error"`
}
