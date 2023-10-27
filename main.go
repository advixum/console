package main

import (
	db "console/database"
	"console/handlers"
	"console/logging"
	"console/models"
	"flag"

	"github.com/gin-gonic/contrib/secure"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var (
	log      = logging.Config
	security = secure.Options{
		AllowedHosts:          []string{"127.0.0.1:8080", "example.com:443"},
		SSLRedirect:           false, // true if not behind nginx
		SSLHost:               "example.com:443",
		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "http"},
		STSSeconds:            315360000,
		STSIncludeSubdomains:  true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'",
	}
	host = flag.String("host", "localhost", "Redis host")
	port = flag.Int("port", 6379, "Redis port")
)

func main() {
	// Database init
	db.Connect()
	db.C.AutoMigrate(&models.Users{})

	// Redis init
	flag.Parse()
	handlers.InitRedis(*host, *port)

	// Run router
	r := router()
	r.Run("127.0.0.1:8080")
}

func router() *gin.Engine {
	// Gin settings
	r := gin.New()
	r.SetTrustedProxies([]string{"127.0.0.1"})
	r.Use(gin.LoggerWithWriter(log.WriterLevel(logrus.InfoLevel)))
	r.Use(gin.RecoveryWithWriter(log.WriterLevel(logrus.ErrorLevel)))
	r.Use(secure.Secure(security))

	// Routes
	r.POST("/redis/incr", handlers.Incr)
	r.POST("/sign/hmacsha512", handlers.HMAC)
	r.POST("/postgres/users", handlers.User)
	return r
}
