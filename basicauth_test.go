package basicauth

import (
	"reflect"
	"net/http/httptest"
	"net/http"
	"testing"
	"bytes"
	"encoding/base64"

	"github.com/lunny/tango"
)

type AuthAction struct {}
func (a *AuthAction) Get() string {
	return "200"
}

func TestBasicAuthCorrect(t *testing.T) {
	const user, pass = "lunny", "lunny"
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	tg.Use(NewBasicAuth(user, pass))
	tg.Get("/", new(AuthAction))

	req, err := http.NewRequest("GET", "http://localhost:8000/", nil)
	if err != nil {
		t.Error(err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	req.Header.Set("Authorization", "Basic "+auth)

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
}

func TestBasicAuthError(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	tg.Use(NewBasicAuth("lunny", "lunny"))
	tg.Get("/", new(AuthAction))

	req, err := http.NewRequest("GET", "http://localhost:8000/", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusUnauthorized)
	refute(t, len(buff.String()), 0)
}

type NoAuthAction struct {
	NoAuth
}
func (a *NoAuthAction) Get() string {
	return "200"
}

func TestBasicAuthNoAuth(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	tg.Use(NewBasicAuth("lunny", "lunny"))
	tg.Get("/", new(NoAuthAction))

	req, err := http.NewRequest("GET", "http://localhost:8000/", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), "200")
}


/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func refute(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		t.Errorf("Did not expect %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}
