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

	e, err := casbin.NewCachedEnforcer(viper.GetString("MODEL_PATH"), a)
	if err != nil {
		log.Fatalf("error: new enforcer: %s", err)
	}

	// Load the policy from DB.
	err = e.LoadPolicy()
	if err != nil {
		log.Fatalf("error: load policy: %s", err)
		return
	}

	hdl := &handler{e: e}

	mux := http.NewServeMux()
	mux.HandleFunc("/", hdl.HelloHandler)
	mux.HandleFunc("/time", hdl.CurrentTimeHandler)
	mux.HandleFunc("/protected", hdl.ProtectedHandler)
	mux.HandleFunc("/roles", hdl.RolesHandler)
	mux.HandleFunc("/init", hdl.InitHandler)

	host := fmt.Sprintf(":%d", viper.GetInt("APP_PORT"))
	log.Infof("Starting application http://localhost%s", host)

	if err = http.ListenAndServe(host, hdl.middleware(mux)); err != nil {
		log.Fatalf("error: listen and serve: %s", err)
		return
	}
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

// handler
type handler struct {
	e *casbin.CachedEnforcer
}

// middleware is a middleware that enforces authorization.
func (h *handler) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		user := r.Header.Get("user")
		url := r.URL.RequestURI()

		log.Info().
			Interface("Header", r.Header.Clone()).
			Interface("url", url).
			Msg("middleware logger")

		log.Info().
			Interface("policies", h.e.GetAllSubjects()).
			Msg("list roles")

		if url != "/init" {
			ok, _ := h.e.Enforce(user, url)
			if !ok {
				responseWithJson(w, http.StatusUnauthorized, "The current user ("+user+") is not allowed to execute "+url+"\n")
				return
			}
		}

		next.ServeHTTP(w, r)
		return
	})
}

// HelloHandler returns "Hello, World!".
func (h *handler) HelloHandler(w http.ResponseWriter, r *http.Request) {
	responseWithJson(w, http.StatusOK, "Hello, World!")
}

// CurrentTimeHandler returns the current time.
func (h *handler) CurrentTimeHandler(w http.ResponseWriter, r *http.Request) {
	curTime := time.Now().Format(time.RFC3339)

	responseWithJson(w, http.StatusOK, fmt.Sprintf("the current time is %v", curTime))
}

// ProtectedHandler returns "Protected" if passed.
func (h *handler) ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	responseWithJson(w, http.StatusOK, "Protect passed")
}

// RolesHandler returns the roles of the current user.
func (h *handler) RolesHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("user")

	roles, err := h.e.GetRolesForUser(user)
	if err != nil {
		log.Err(err).Msg("Failed to get roles for user")
		responseWithJson(w, http.StatusInternalServerError, err.Error())
		return
	}

	responseWithJson(w, http.StatusOK, roles)
}

// InitHandler initializes the role.
func (h *handler) InitHandler(w http.ResponseWriter, r *http.Request) {

	// Modify the policy.
	h.e.AddPolicy("role:user", "/")
	h.e.AddPolicy("role:user", "/time")

	h.e.AddPolicy("role:admin", "/*")

	h.e.AddPolicy("*", "/")

	h.e.AddGroupingPolicy("xdorro", "role:admin")
	h.e.AddGroupingPolicy("ahihi", "role:user")

	// Save the policy back to DB.
	err := h.e.SavePolicy()
	if err != nil {
		log.Fatalf("error: save policy: %s", err)
		return
	}

	responseWithJson(w, http.StatusOK, "OK")
}
