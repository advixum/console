package main

import (
	"bytes"
	db "console/database"
	"console/handlers"
	"console/models"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

// Requirements: .env PostgreSQL credentials

var (
	cRedis *redis.Client
)

func init() {
	ctx := context.Background()
	cRedis = redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%v:%v", *host, *port), // default flag value was used
		DB:   1,
	})
	_, err := cRedis.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Redis connection failed: %v", err)
	}
}

// Testing data processing in the handlers.Incr() function.
func TestIncrHandling(t *testing.T) {
	type args struct {
		key   string
		value int
		valid bool
	}
	tests := []struct {
		test string
		args args
	}{
		{
			test: "Valid data was handled",
			args: args{
				key:   "age",
				value: 19,
				valid: true,
			},
		},
		{
			test: "Empty key was rejected",
			args: args{
				key:   "",
				value: 19,
				valid: false,
			},
		},
		{
			test: "Data without key was rejected",
			args: args{
				value: 19,
				valid: false,
			},
		},
		{
			test: "Data without value was rejected",
			args: args{
				key:   "age",
				valid: false,
			},
		},
		{
			test: "Empty data was rejected",
			args: args{
				valid: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			// Setup test mode
			gin.SetMode(gin.TestMode)

			// Redis init
			flag.Parse()
			handlers.InitRedis(*host, *port)

			// Create testing data
			type data struct {
				Key   string `json:"key"`
				Value int    `json:"value"`
			}
			send := data{
				Key:   tt.args.key,
				Value: tt.args.value,
			}
			jsonData, err := json.Marshal(send)
			assert.NoError(t, err)

			// Setup router
			r := router()
			request, err := http.NewRequest(
				"POST",
				"http://127.0.0.1:8080/redis/incr",
				bytes.NewBuffer(jsonData),
			)
			assert.NoError(t, err)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			r.ServeHTTP(response, request)

			// Clean database values
			ctx := context.Background()
			_, err = cRedis.FlushAll(ctx).Result()
			assert.NoError(t, err)

			// Estimation of values
			if tt.args.valid {
				assert.Equal(t, 200, response.Code)
				assert.NoError(t, err)
				assert.JSONEq(
					t,
					fmt.Sprintf(`{"value": %v}`, tt.args.value),
					response.Body.String(),
				)
			} else {
				assert.NotEqual(t, 200, response.Code)
			}
		})
	}
}

// Testing data incrementing in the handlers.Incr() function.
func TestIncrIncrementing(t *testing.T) {
	type args struct {
		key   string
		value int
		check bool
	}
	tests := []struct {
		test string
		args args
	}{
		{
			test: "Initial request",
			args: args{
				key:   "age",
				value: 19,
				check: false,
			},
		},
		{
			test: "Modified request",
			args: args{
				key:   "age",
				value: 19,
				check: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			// Setup test mode
			gin.SetMode(gin.TestMode)

			// Redis init
			flag.Parse()
			handlers.InitRedis(*host, *port)

			// Create testing data
			type data struct {
				Key   string `json:"key"`
				Value int    `json:"value"`
			}
			send := data{
				Key:   tt.args.key,
				Value: tt.args.value,
			}
			jsonData, err := json.Marshal(send)
			assert.NoError(t, err)

			// Setup router
			r := router()
			request, err := http.NewRequest(
				"POST",
				"http://127.0.0.1:8080/redis/incr",
				bytes.NewBuffer(jsonData),
			)
			assert.NoError(t, err)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			r.ServeHTTP(response, request)

			// Estimation of values
			if tt.args.check {
				assert.Equal(t, 200, response.Code)
				assert.NoError(t, err)
				assert.JSONEq(
					t,
					`{"value": 38}`,
					response.Body.String(),
				)
				ctx := context.Background()
				_, err = cRedis.FlushAll(ctx).Result()
				assert.NoError(t, err)
			} else {
				assert.Equal(t, 200, response.Code)
			}
		})
	}
}

// Testing data processing in the handlers.HMAC() function.
func TestHMAC(t *testing.T) {
	type args struct {
		text  string
		key   string
		valid bool
	}
	tests := []struct {
		test string
		args args
	}{
		{
			test: "Valid data was handled",
			args: args{
				text:  "test",
				key:   "test123",
				valid: true,
			},
		},
		{
			test: "Empty text was rejected",
			args: args{
				text:  "",
				key:   "test123",
				valid: false,
			},
		},
		{
			test: "Empty key was rejected",
			args: args{
				text:  "test",
				key:   "",
				valid: false,
			},
		},
		{
			test: "Data without text was rejected",
			args: args{
				key:   "test123",
				valid: false,
			},
		},
		{
			test: "Data without key was rejected",
			args: args{
				text:  "test",
				valid: false,
			},
		},
		{
			test: "Empty data was rejected",
			args: args{
				valid: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			// Setup test mode
			gin.SetMode(gin.TestMode)

			// Create testing data
			type data struct {
				Text string `json:"text"`
				Key  string `json:"key"`
			}
			send := data{
				Text: tt.args.text,
				Key:  tt.args.key,
			}
			jsonData, err := json.Marshal(send)
			assert.NoError(t, err)

			// Setup router
			r := router()
			request, err := http.NewRequest(
				"POST",
				"http://127.0.0.1:8080/sign/hmacsha512",
				bytes.NewBuffer(jsonData),
			)
			assert.NoError(t, err)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			r.ServeHTTP(response, request)

			// Estimation of values
			if tt.args.valid {
				assert.Equal(t, 200, response.Code)
				assert.NoError(t, err)
				assert.Equal(
					t,
					"\"b596e24739fd44d42ffd25f26ea367dad3a71f61c8c5fab6b6ee6ceeae5a7170b66445d6eaadfb49e6d4e968a2888726ff522e3bf065c966aa66a24153778382\"",
					response.Body.String(),
				)
			} else {
				assert.NotEqual(t, 200, response.Code)
			}
		})
	}
}

// Testing data processing in the handlers.User() function.
func TestUser(t *testing.T) {
	type args struct {
		name  string
		age   int
		valid bool
	}
	tests := []struct {
		test string
		args args
	}{
		{
			test: "Valid data was saved",
			args: args{
				name:  "Alex",
				age:   21,
				valid: true,
			},
		},
		{
			test: "Empty name was rejected",
			args: args{
				name:  "",
				age:   21,
				valid: false,
			},
		},
		{
			test: "Data without name was rejected",
			args: args{
				age:   21,
				valid: false,
			},
		},
		{
			test: "Less than 2 letters name was rejected",
			args: args{
				name:  "A",
				age:   21,
				valid: false,
			},
		},
		{
			test: "More than 50 letters name was rejected",
			args: args{
				name: `
				Nnnnnnnnnn
				Nnnnnnnnnn
				Nnnnnnnnnn
				Nnnnnnnnnn
				NnnnnnnnnnN
			`,
				age:   21,
				valid: false,
			},
		},
		{
			test: "Name with numbers was rejected",
			args: args{
				name:  "Alex1",
				age:   21,
				valid: false,
			},
		},
		{
			test: "Name with symbols was rejected",
			args: args{
				name:  "Alex!",
				age:   21,
				valid: false,
			},
		},
		{
			test: "Data without age was rejected",
			args: args{
				name:  "Alex",
				valid: false,
			},
		},
		{
			test: "Less than 1 age was rejected",
			args: args{
				name:  "Alex",
				age:   0,
				valid: false,
			},
		},
		{
			test: "More than 120 age was rejected",
			args: args{
				name:  "Alex",
				age:   121,
				valid: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			// Setup test database
			gin.SetMode(gin.TestMode)
			db.Connect()
			db.C.AutoMigrate(&models.Users{})
			defer db.C.Migrator().DropTable(&models.Users{})

			// Create testing data
			type data struct {
				Name string `json:"name"`
				Age  int    `json:"age"`
			}
			send := data{
				Name: tt.args.name,
				Age:  tt.args.age,
			}
			jsonData, err := json.Marshal(send)
			assert.NoError(t, err)

			// Setup router
			r := router()
			request, err := http.NewRequest(
				"POST",
				"http://127.0.0.1:8080/postgres/users",
				bytes.NewBuffer(jsonData),
			)
			assert.NoError(t, err)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			r.ServeHTTP(response, request)

			// Get database values
			var entry models.Users
			err = db.C.First(&entry).Error

			// Estimation of values
			if tt.args.valid {
				assert.Equal(t, 200, response.Code)
				assert.NoError(t, err)
				assert.JSONEq(
					t,
					`{"id": 1}`,
					response.Body.String(),
				)
				assert.Equal(
					t,
					entry.User,
					fmt.Sprintf(`("%v", %v)`, tt.args.name, tt.args.age),
				)
			} else {
				assert.NotEqual(t, 200, response.Code)
				assert.Error(t, err)
			}
		})
	}
}
