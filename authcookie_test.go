package authcookie

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	secret := []byte("secret key")
	good := "AAAAAAAAACpoZWxsbyB3b3JsZGVALSOGOVVAdyTB0vn84OQW4A3jBOiwW2Leyw-SrUCq"
	c := New("hello world", time.Unix(42, 0), secret)
	if c != good {
		t.Errorf("expected %q, got %q", good, c)
	}
	// Test empty login
	c = New("", time.Unix(42, 0), secret)
	if c != "" {
		t.Errorf(`allowed empty login: got %q, expected ""`, c)
	}
}

func TestParse(t *testing.T) {
	// good
	sec := time.Now()
	login := "bender"
	key := []byte("another secret key")
	c := New(login, sec, key)
	l, e, err := Parse(c, key)
	if err != nil {
		t.Errorf("error parsing valid cookie: %s", err)
	}
	if l != login {
		t.Errorf("login: expected %q, got %q", login, l)
	}
	//NOTE: comparing at the level of seconds is perfectly adequate here.
	if e.Unix() != sec.Unix() {
		t.Errorf("expiration: expected %v, got %v", sec, e)
	}
	// bad
	key = []byte("secret key")
	bad := []string{
		"",
		"AAAAKvgQ2I_RGePVk9oAu55q-Valnf__Fx_hlTM-dLwYxXOf",
		"badcookie",
		"AAAAAAAAACpiZW5kZXKysL3WMPerrpRDuugQXcnF9lZSpQZVl7gWo3WuiDt2qA==",
		"zAAAAAAACpiZW5kZXKysL3WMPxvbpRDuugQXcnF9lZSpQZVl7gWo3WuiDt2qA==",
		"AAAAAAAAACpiZW5kZXKysL3WMPxvbpRDuugQXcnF9lZSpQZVerrWo3WuiDt2qA==",
	}
	for _, v := range bad {
		_, _, err := Parse(v, key)
		if err == nil {
			t.Errorf("bad cookie didn't return error: %q", v)
		}
	}
}

func TestLogin(t *testing.T) {
	login := "~~~!|zoidberg|!~~~"
	key := []byte("(:€")
	exp := time.Now().Add(time.Second * 120)
	c := New(login, exp, key)
	l := Login(c, key)
	if l != login {
		t.Errorf("login: expected %q, got %q", login, l)
	}
	c = "no" + c
	l = Login(c, key)
	if l != "" {
		t.Errorf("login expected empty string, got %q", l)
	}
	exp = time.Now().Add(-(time.Second * 30))
	c = New(login, exp, key)
	l = Login(c, key)
	if l != "" {
		t.Errorf("returned login from expired cookie")
	}
}
