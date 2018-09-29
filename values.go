package security

type RememberingUserValuers struct {
	HTTPFormValidator

	PID            string
	Password       string
	ShouldRemember string

	Arbitrary map[string]string
}

func (r RememberingUserValuers) GetPID() string {
	return r.PID
}

func (r RememberingUserValuers) GetPassword() string {
	return r.Password
}

func (r RememberingUserValuers) GetShouldRemember() bool {
	return r.ShouldRemember != ""
}
