package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"text/template"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	Token       string `json:"token,omitempty" bson:"token,omitempty"`
	Name        string `json:"name,omitempty" bson:"name,omitempty"`
	Email       string `json:"email,omitempty" bson:"email,omitempty"`
	Password    string `json:"password,omitempty" bson:"password,omitempty"`
	LoginTime   string `json:"loginTime,omitempty" bson:"loginTime,omitempty"`
	LogoutTime  string `json:"logoutTime,omitempty" bson:"logoutTime,omitempty"`
	Age         string `json:"age,omitempty" bson:"age,omitempty"`
	DOB         string `json:"dob,omitempty" bson:"dob,omitempty"`
	Gender      string `json:"gender,omitempty" bson:"gender,omitempty"`
	Nationality string `json:"nationality,omitempty" bson:"nationality,omitempty"`
	Occupation  string `json:"occupation,omitempty" bson:"occupation,omitempty"`
}

type Appointment struct {
	Date   string `json:"date,omitempty" bson:"date,omitempty"`
	Time   string `json:"time,omitempty" bson:"time,omitempty"`
	UserId string `json:"userId,omitempty" bson:"userId,omitempty"`
	Status string `json:"status,omitempty" bson:"status,omitempty"`
}

var client *mongo.Client

func tokenGenerator() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func signup(response http.ResponseWriter, request *http.Request) {
	fmt.Println("Sign Up")
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	var user User
	var dbUser User
	json.NewDecoder(request.Body).Decode(&user)
	// collection := client.Database("happilyeverafter").Collection("Users")
	collection := client.Database("happilyeverco-dev").Collection("Users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, User{Email: user.Email}).Decode(&dbUser)
	if err == nil {
		fmt.Println(err)
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": User already exists }`))
		return
	}
	user.Token = tokenGenerator()
	currtime := strings.Split(time.Now().String(), ".")[0]
	user.LoginTime = currtime
	result, _ := collection.InsertOne(ctx, user)
	json.NewEncoder(response).Encode(result)
}

func login(response http.ResponseWriter, request *http.Request) {
	fmt.Println("Login")
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	// collection := client.Database("happilyeverafter").Collection("Users")
	collection := client.Database("happilyeverco-dev").Collection("Users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	var dbUser bson.M
	cursor, err := collection.Find(ctx, bson.M{"email": user.Email, "password": user.Password})
	if err != nil {
		// fmt.Println(err)
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": Email or Password Incorrect }`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		if err = cursor.Decode(&dbUser); err != nil {
			log.Fatal(err)
		}
	}
	currtime := strings.Split(time.Now().String(), ".")[0]
	filter := bson.M{"email": user.Email}
	update := bson.M{"$set": bson.M{"loginTime": currtime}}
	er := collection.FindOneAndUpdate(ctx, filter, update)
	if er == nil {
		fmt.Println(er)
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": Login Failed }`))
		return
	}
	json.NewEncoder(response).Encode(dbUser)
}

func logout(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	currtime := strings.Split(time.Now().String(), ".")[0]
	uniqueToken := tokenGenerator()
	// collection := client.Database("happilyeverafter").Collection("Users")
	collection := client.Database("happilyeverco-dev").Collection("Users")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	filter := bson.M{"_id": id}
	update := bson.M{"$set": bson.M{"token": uniqueToken, "logoutTime": currtime}}
	err := collection.FindOneAndUpdate(ctx, filter, update)
	if err == nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func getUser(response http.ResponseWriter, request *http.Request) {
	// fmt.Println("User entered GET")
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	// fmt.Println(id)
	// collection := client.Database("happilyeverafter").Collection("Users")
	collection := client.Database("happilyeverco-dev").Collection("Users")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	var user bson.M
	cursor, err := collection.Find(ctx, bson.M{"_id": id})
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "User does not exist" }`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		if err = cursor.Decode(&user); err != nil {
			log.Fatal(err)
		}
		// fmt.Println(user)
	}
	// fmt.Println("---")
	// fmt.Println(user)
	json.NewEncoder(response).Encode(user)
}

func updateUser(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	params := mux.Vars(request)
	// fmt.Println("Req Body  ", request.Body)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	// fmt.Printf("%T", user.DOB);
	// collection := client.Database("happilyeverafter").Collection("Users")
	collection := client.Database("happilyeverco-dev").Collection("Users")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	filter := bson.M{"_id": id}
	update := bson.M{"$set": user}
	err := collection.FindOneAndUpdate(ctx, filter, update)
	if err.Err() != nil {
		// fmt.Println("ERROR")
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "User does not exist" }`))
		return
	} else {
		// fmt.Println("UPDATED")
		response.WriteHeader(http.StatusAccepted)
		response.Write([]byte(`{ "message": "Updated" }`))
	}
}

func appointment(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	var appointment Appointment
	json.NewDecoder(request.Body).Decode(&appointment)
	appointment.Status = "Call Scheduled"
	// collection := client.Database("happilyeverafter").Collection("Appointments")
	collection := client.Database("happilyeverco-dev").Collection("Appointments")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	result, _ := collection.InsertOne(ctx, appointment)

	collection = client.Database("happilyeverafter").Collection("Users")
	var user User
	cursor, err := collection.Find(ctx, bson.M{"_id": appointment.UserId})
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		if err = cursor.Decode(&user); err != nil {
			log.Fatal(err)
		}
	}

	sendEmail(appointment.Date, appointment.Time, user.Email)
	json.NewEncoder(response).Encode(result)
}

func getAppointment(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	params := mux.Vars(request)
	userId := params["id"]
	// collection := client.Database("happilyeverafter").Collection("Appointments")
	collection := client.Database("happilyeverco-dev").Collection("Appointments")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	var appointment bson.M
	cursor, err := collection.Find(ctx, bson.M{"UserId": userId})
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "User does not exist" }`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		if err = cursor.Decode(&appointment); err != nil {
			log.Fatal(err)
		}
		// fmt.Println(user)
	}
	// fmt.Println("---")
	// fmt.Println(user)
	json.NewEncoder(response).Encode(appointment)
}

func sendEmail(date string, time string, email string) {
	from := "support@happilyever.co"
	password := "S@pp0rth@a@!y"
	// Receiver email address.
	to := []string{
		email,
	}
	// smtp server configuration.
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	// Authentication.
	auth := smtp.PlainAuth("", from, password, smtpHost)

	t, _ := template.ParseFiles("emailTemplate.html")
	var body bytes.Buffer
	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body.Write([]byte(fmt.Sprintf("Subject: Link for zoom call with our agent \n%s\n\n", mimeHeaders)))
	t.Execute(&body, struct {
		Date string
		Time string
	}{
		Date: date,
		Time: time,
	})
	// Sending email.
	er := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, body.Bytes())
	if er != nil {
		fmt.Println(er)
		return
	}
	fmt.Println("Email Sent!")
}

func forgotPwd(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	// collection := client.Database("happilyeverafter").Collection("Users")
	collection := client.Database("happilyeverco-dev").Collection("Users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	var dbUser User
	err := collection.FindOne(ctx, User{Email: user.Email}).Decode(&dbUser)
	if err != nil {
		// fmt.Println(err)
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": User does not exist }`))
		return
	}
	sendOtp(user.Email, dbUser.Token)
	json.NewEncoder(response).Encode(dbUser)
}

// send otp
func sendOtp(email string, otp string) {
	from := "support@happilyever.co"
	password := "S@pp0rth@a@!y"
	// Receiver email address.
	to := []string{
		email,
	}
	// smtp server configuration.
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	// Authentication.
	auth := smtp.PlainAuth("", from, password, smtpHost)

	t, _ := template.ParseFiles("otpTemplate.html")
	var body bytes.Buffer
	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body.Write([]byte(fmt.Sprintf("Subject: Request to change password \n%s\n\n", mimeHeaders)))
	t.Execute(&body, struct {
		OTP string
	}{
		OTP: otp,
	})
	// Sending email.
	er := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, body.Bytes())
	if er != nil {
		fmt.Println(er)
		return
	}
	fmt.Println("OTP Sent!")
}

func changePwd(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	// fmt.Printf("%T", user.DOB);
	// collection := client.Database("happilyeverafter").Collection("Users")
	collection := client.Database("happilyeverco-dev").Collection("Users")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	newToken := tokenGenerator()
	filter := bson.M{"token": user.Token}
	update := bson.M{"$set": bson.M{"password": user.Password, "token": newToken}}
	err := collection.FindOneAndUpdate(ctx, filter, update)
	if err.Err() != nil {
		// fmt.Println("ERROR")
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "User does not exist" }`))
		return
	} else {
		// fmt.Println("UPDATED")
		response.WriteHeader(http.StatusAccepted)
		response.Write([]byte(`{ "message": "Updated" }`))
	}
}

// func main() {
// 	fmt.Println("Starting the application...")
// 	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
// 	options := options.Client().ApplyURI("mongodb://localhost:27017") //connect to DocumentDB
// 	client, _ = mongo.Connect(ctx, options)
// 	// router := router.Router()
// 	router := mux.NewRouter()
// 	router.HandleFunc("/signup", signup).Methods("POST")
// 	router.HandleFunc("/login", login).Methods("POST")
// 	router.HandleFunc("/logout/{id}", logout).Methods("POST")
// 	router.HandleFunc("/changePwd", changePwd).Methods("PUT")
// 	router.HandleFunc("/forgotPwd", forgotPwd).Methods("POST")
// 	router.HandleFunc("/ops/appointment", appointment).Methods("POST")
// 	router.HandleFunc("/ops/appointment/{id}", getAppointment).Methods("GET")
// 	// router.HandleFunc("/ops/appointmentUpdate", appointmentUpdate).Methods("PUT")
// 	router.HandleFunc("/user/{id}", getUser).Methods("GET")
// 	router.HandleFunc("/user/{id}", updateUser).Methods("PUT")
// 	http.ListenAndServe(":3001", handlers.CORS(handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"}), handlers.AllowedMethods([]string{"GET", "POST", "PUT", "HEAD", "OPTIONS"}), handlers.AllowedOrigins([]string{"*"}))(router))
// }

const (
	// Path to the AWS CA file
	// https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem
	caFilePath = "rds-combined-ca-bundle.pem"

	// Timeout operations after N seconds
	connectTimeout  = 5
	queryTimeout    = 30
	username        = "happilyeverdev"
	password        = "ddbdev260121"
	clusterEndpoint = "happilyeverco-dev.cluster-c3br2ymfzopu.ap-south-1.docdb.amazonaws.com:27017"

	// Which instances to read from
	readPreference = "primaryPreferred"

	connectionStringTemplate = "mongodb://happilyeverdev:ddbdev260121@happilyeverco-dev.cluster-c3br2ymfzopu.ap-south-1.docdb.amazonaws.com:27017/?ssl=true&ssl_ca_certs=rds-combined-ca-bundle.pem&replicaSet=rs0&readPreference=primaryPreferred&retryWrites=false"
)

func main() {
	connectionURI := fmt.Sprintf(connectionStringTemplate, username, password, clusterEndpoint, readPreference)
	tlsConfig, err := getCustomTLSConfig(caFilePath)
	if err != nil {
		log.Fatalf("Failed getting TLS configuration: %v", err)
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(connectionURI).SetTLSConfig(tlsConfig))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to cluster: %v", err)
	}
	// Force a connection to verify our connection string
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to ping cluster: %v", err)
	}
	fmt.Println("Connected to DocumentDB!")

	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/logout/{id}", logout).Methods("POST")
	router.HandleFunc("/changePwd", changePwd).Methods("PUT")
	router.HandleFunc("/forgotPwd", forgotPwd).Methods("POST")
	router.HandleFunc("/ops/appointment", appointment).Methods("POST")
	router.HandleFunc("/ops/appointment/{id}", getAppointment).Methods("GET")
	// router.HandleFunc("/ops/appointmentUpdate", appointmentUpdate).Methods("PUT")
	router.HandleFunc("/user/{id}", getUser).Methods("GET")
	router.HandleFunc("/user/{id}", updateUser).Methods("PUT")
	http.ListenAndServe(":3001", handlers.CORS(handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"}), handlers.AllowedMethods([]string{"GET", "POST", "PUT", "HEAD", "OPTIONS"}), handlers.AllowedOrigins([]string{"*"}))(router))
}

func getCustomTLSConfig(caFile string) (*tls.Config, error) {
	tlsConfig := new(tls.Config)
	certs, err := ioutil.ReadFile(caFile)

	if err != nil {
		return tlsConfig, err
	}
	tlsConfig.RootCAs = x509.NewCertPool()
	ok := tlsConfig.RootCAs.AppendCertsFromPEM(certs)
	if !ok {
		return tlsConfig, errors.New("Failed parsing pem file")
	}
	return tlsConfig, nil
}
