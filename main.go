package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client

type Person struct {
	ID          string `json:"id,omitempty" bson:"id,omitempty"`
	Name        string `json:"name,omitempty" bson:"name,omitempty"`
	Email       string `json:"email,omitempty" bson:"email,omitempty"`
	Password    string `json:"password,omitempty" bson:"password,omitempty"`
	Appointment bool   `json:"appointment,false" bson:"appointment,false"`
	Age         string `json:"age,0" bson:"age,0"`
	Salary      string `json:"salary,0" bson:"salary,0"`
	DOB         string `json:"dob,0" bson:"dob,0"`
}

func signup(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	var user Person
	var dbUser Person
	json.NewDecoder(request.Body).Decode(&user)
	collection := client.Database("happilyeverafter").Collection("Users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, Person{Email: user.Email}).Decode(&dbUser)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": User already exists }`))
		return
	}
	result, _ := collection.InsertOne(ctx, user)
	json.NewEncoder(response).Encode(result)
}

func login(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	var user Person
	json.NewDecoder(request.Body).Decode(&user)
	// fmt.Println(user.Email)
	// fmt.Println(user.Password)
	collection := client.Database("happilyeverafter").Collection("Users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	var dbUser bson.M
	cursor, err := collection.Find(ctx, bson.M{"email": user.Email, "password": user.Password})
	if err != nil {
		fmt.Println(err)
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
	json.NewEncoder(response).Encode(dbUser)
}

func getUser(response http.ResponseWriter, request *http.Request) {
	// fmt.Println("User entered GET")
	response.Header().Set("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	// fmt.Println(id)
	collection := client.Database("happilyeverafter").Collection("Users")
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
	var user Person
	json.NewDecoder(request.Body).Decode(&user)
	// fmt.Printf("%T", user.DOB);
	collection := client.Database("happilyeverafter").Collection("Users")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	filter := bson.M{"_id": id}
	// update := bson.M{"$set": user}
	update := bson.M{"$set": bson.M{"dob": user.DOB}}
	if user.Salary != "" {
		update = bson.M{"$set": bson.M{"salary": user.Salary}}
	}
	if user.Age != "" {
		update = bson.M{"$set": bson.M{"age": user.Age}}
	}
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

func main() {
	fmt.Println("Starting the application...")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	options := options.Client().ApplyURI("mongodb://localhost:27017") //connect to DocumentDB
	client, _ = mongo.Connect(ctx, options)
	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/user/{id}", getUser).Methods("GET")
	router.HandleFunc("/user/{id}", updateUser).Methods("PUT")
	http.ListenAndServe(":8080", handlers.CORS(handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"}), handlers.AllowedMethods([]string{"GET", "POST", "PUT", "HEAD", "OPTIONS"}), handlers.AllowedOrigins([]string{"*"}))(router))
}
