package main

import (
	"AuthProto"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

func main() {

	fmt.Println("[ROS] Server starting...")

	http.HandleFunc("/LoginEncrypt", func(writer http.ResponseWriter, request *http.Request) {
		err := request.ParseForm()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(writer, base64.StdEncoding.EncodeToString(AuthProto.EncryptPacket([]byte("ticket=&platformName=pcros&email="+url.QueryEscape(request.PostFormValue("email"))+"&nickname=&password="+request.PostFormValue("password")))))
	})

	http.HandleFunc("/DecryptPacket", func(writer http.ResponseWriter, request *http.Request) {

		err := request.ParseForm()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		buff, err := base64.StdEncoding.DecodeString(request.PostFormValue("packet"))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		decrypted, err := AuthProto.DecryptPacket(buff)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(writer, base64.StdEncoding.EncodeToString(decrypted))
	})

	http.HandleFunc("/GenUserAgent", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, AuthProto.CreateUserAgent())
	})

	http.HandleFunc("/HeartBeat", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "* Core HeartBeat *")
	})

	log.Fatal(http.ListenAndServe(":8080", nil))

}
