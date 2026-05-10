package auth

type SimpleAuth struct {
	Username string
	Password string
}

func (sa *SimpleAuth) CheckPasswd(name, pass string) (bool, error) {
	if name == sa.Username && pass == sa.Password {
		return true, nil
	}
	return false, nil
}
