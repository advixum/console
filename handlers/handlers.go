package handlers

import (
	db "console/database"
	"console/logging"
	"console/models"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var (
	cRedis *redis.Client
	log    = logging.Config
)

// This function triggers Redis connection.
func InitRedis(host string, port int) {
	ctx := context.Background()
	db := 0
	if gin.Mode() == gin.TestMode {
		db = 1
	}
	cRedis = redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%v:%v", host, port),
		DB:   db,
	})
	_, err := cRedis.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Redis connection failed: %v", err)
	}
	log.Infof("Redis DB: %v", db)
}

// Handler stores data with key in Redis using optimistic locking. If
// the key does not exist, a new record is created, otherwise the
// existing one is incremented by the incoming value. Return JSON with
// the value or an error with its cause.
func Incr(c *gin.Context) {
	f := logging.F()
	var request struct {
		Key   string `json:"key" binding:"required"`
		Value int    `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		log.Debug(f+"parsing failed: ", err)
		c.JSON(422, gin.H{"error": "Invalid query"})
		return
	}
	if request.Key == "" {
		c.JSON(422, gin.H{"error": "Key cannot be empty"})
		return
	}
	log.WithFields(logrus.Fields{
		"Key":   request.Key,
		"Value": request.Value,
	}).Debug(f + "request Incr")
	ctx := context.Background()
	response := 0
REDIS:
	for { // Start optimistic locking
		err := cRedis.Watch(ctx, func(tx *redis.Tx) error {
			oldData, err := tx.Get(ctx, request.Key).Result()
			var cache struct {
				Value int `json:"value"`
			}
			switch {
			case err == redis.Nil:
				log.Info(f + "Create new key")
				cache.Value = request.Value
				jsonData, err := json.Marshal(cache)
				if err != nil {
					log.Error(f+"Serializing new data failed: %v", err)
					return err
				}
				_, err = tx.TxPipelined(
					ctx,
					func(pipe redis.Pipeliner) error {
						expiration := 30 * time.Minute
						pipe.Set(ctx, request.Key, jsonData, expiration)
						return nil
					},
				)
				if err != nil {
					return err
				}
				response = cache.Value
				return nil
			case err != nil && err != redis.Nil:
				return err
			}
			if oldData != "" {
				err := json.Unmarshal([]byte(oldData), &cache)
				if err != nil {
					log.Error(f+"Cache deserializing failed: %v", err)
					return err
				}
			}
			cache.Value = cache.Value + request.Value
			response = cache.Value
			jsonData, err := json.Marshal(cache)
			if err != nil {
				log.Error(f+"Serializing modified data failed: %v", err)
				return err
			}
			_, err = tx.TxPipelined(
				ctx,
				func(pipe redis.Pipeliner) error {
					expiration := 30 * time.Minute
					pipe.Set(ctx, request.Key, jsonData, expiration)
					return nil
				},
			)
			if err != nil {
				return err
			}
			return nil
		}, request.Key)
		switch {
		case err == redis.TxFailedErr:
			continue
		case err != nil:
			log.Errorf(f+"Unexpected POST loop error: %v", err)
			continue
		default:
			log.Infof(f+"Success handling for '%v' key", request.Key)
			break REDIS
		}
	}
	c.JSON(200, gin.H{"value": response})
}

// Handler for generating a signature of a value "text" using the key
// "key". Return the HMAC-SHA512 signature as a hex string or JSON with
// the error and its cause.
func HMAC(c *gin.Context) {
	f := logging.F()
	var request struct {
		Text string `json:"text" binding:"required"`
		Key  string `json:"key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		log.Debug(f+"parsing failed: ", err)
		c.JSON(422, gin.H{"error": "Invalid query"})
		return
	}
	switch {
	case request.Text == "":
		c.JSON(422, gin.H{"error": "Text cannot be empty"})
		return
	case request.Key == "":
		c.JSON(422, gin.H{"error": "Key cannot be empty"})
		return
	}
	log.WithFields(logrus.Fields{
		"Text": request.Text,
		"Key":  request.Key,
	}).Debug(f + "request HMAC")
	keyBytes := []byte(request.Key)
	h := hmac.New(sha512.New, keyBytes)
	h.Write([]byte(request.Text))
	signature := h.Sum(nil)
	signatureHex := hex.EncodeToString(signature)
	c.JSON(200, signatureHex)
}

// Handler for creating a user record in the database. Return JSON with
// the new user id or an error with its cause.
func User(c *gin.Context) {
	f := logging.F()
	var request struct {
		Name string `json:"name" binding:"required"`
		Age  int    `json:"age" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		log.Debug(f+"parsing failed: ", err)
		c.JSON(422, gin.H{"error": "Invalid query"})
		return
	}
	namePattern := `^[a-zA-Zа-яА-Я]+$`
	switch {
	case request.Name == "":
		c.JSON(422, gin.H{"error": "Name cannot be empty"})
		return
	case len(request.Name) < 2:
		c.JSON(422, gin.H{"error": "Name is too short"})
		return
	case len(request.Name) > 50:
		c.JSON(422, gin.H{"error": "Name is too long"})
		return
	case !regexp.MustCompile(namePattern).MatchString(request.Name):
		c.JSON(422, gin.H{"error": "Name contains invalid characters"})
		return
	case request.Age < 1 || request.Age > 120:
		c.JSON(422, gin.H{"error": "Invalid age value"})
		return
	}
	log.WithFields(logrus.Fields{
		"Name": request.Name,
		"Age":  request.Age,
	}).Debug(f + "request User")
	var entry models.Users
	entry.User = fmt.Sprintf(`("%v", %v)`, request.Name, request.Age)
	log.WithFields(logrus.Fields{
		"User": entry.User,
	}).Debug(f + "entry data")
	err := db.C.Create(&entry).Error
	if err != nil {
		log.Errorf(f+"Failed to create entry: ", err)
		c.JSON(500, gin.H{"error": "Failed to create entry"})
		return
	}
	c.JSON(200, gin.H{"id": entry.ID})
}
