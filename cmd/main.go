package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/casbin/casbin/v2"
	mongodbadapter "github.com/casbin/mongodb-adapter/v3"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/xdorro/golang-casbin-example/config"
	"github.com/xdorro/golang-casbin-example/pkg/log"
)

func main() {
	// Init config
	config.InitConfig()

	// Initialize a MongoDB adapter with NewAdapterWithClientOption:
	// The adapter will use custom mongo client options.
	// custom database name.
	// default collection name 'casbin_rule'.
	mongoClientOption := options.Client().ApplyURI(viper.GetString("DB_URL"))
	databaseName := viper.GetString("DB_NAME")
	a, err := mongodbadapter.NewAdapterWithClientOption(mongoClientOption, databaseName, 10*time.Second)
	// Or you can use NewAdapterWithCollectionName for custom collection name.
	if err != nil {
		panic(err)
	}

	e, err := casbin.NewEnforcer(viper.GetString("MODEL_PATH"), a)
	if err != nil {
		log.Fatalf("error: new enforcer: %s", err)
	}

	// Load the policy from DB.
	err = e.LoadPolicy()
	if err != nil {
		log.Fatalf("error: load policy: %s", err)
		return
	}

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// e.AddPolicy("user", "/", "*")
	// e.AddPolicy("user", "/time", "*")
	//
	// e.AddPolicy("admin", "/*", "*")
	//
	// // Save the policy back to DB.
	// err = e.SavePolicy()
	// if err != nil {
	// 	log.Fatalf("error: save policy: %s", err)
	// 	return
	// }

	mux := http.NewServeMux()
	mux.Handle("/", HelloHandler())
	mux.Handle("/time", CurrentTimeHandler())
	mux.Handle("/protected", ProtectedHandler())

	host := fmt.Sprintf(":%d", viper.GetInt("APP_PORT"))
	log.Infof("Starting application http://localhost%s", host)

	if err = http.ListenAndServe(host, middleware(e, mux)); err != nil {
		log.Fatalf("error: listen and serve: %s", err)
		return
	}
}

// HelloHandler returns "Hello, World!".
func HelloHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseWithJson(w, http.StatusOK, "Hello, World!")
	})
}

// CurrentTimeHandler returns the current time.
func CurrentTimeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		curTime := time.Now().Format(time.RFC3339)

		responseWithJson(w, http.StatusOK, fmt.Sprintf("the current time is %v", curTime))
	})
}

// ProtectedHandler returns "Protected" if passed.
func ProtectedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseWithJson(w, http.StatusOK, "Protect passed")
	})
}

// middleware is a middleware that enforces authorization.
func middleware(e *casbin.Enforcer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info().Interface("RequestURI", r.RequestURI).Msg("middleware logger")

		role := r.Header.Get("role")
		resource := r.URL.RequestURI()
		method := r.Method

		if role == "" {
			responseWithJson(w, http.StatusUnauthorized, fmt.Sprintf("no role assigned"))
			return
		}

		// check if the user has permission to access the resource.
		allowed, err := e.Enforce(role, resource, "*")
		if err != nil {
			log.Err(err).Msg("Failed to enforce")
			responseWithJson(w, http.StatusInternalServerError, err.Error())
			return
		}

		// if the user has permission to access the resource, then pass the request to the next handler.
		if allowed {
			next.ServeHTTP(w, r)
			return
		}

		// if the user doesn't have permission to access the resource, then return 401.
		responseWithJson(w, http.StatusUnauthorized, "The current role ("+role+") is not allowed to execute "+resource+" ["+method+"]\n")
	})
}

// responseWithJson writes a json response.
func responseWithJson(w http.ResponseWriter, status int, object any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	err := json.NewEncoder(w).Encode(object)
	if err != nil {
		log.Err(err).Msg("Failed to encode json")
		return
	}
}
