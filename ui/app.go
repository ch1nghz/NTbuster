package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
)

func main() {
	type CrackRequest struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Target     string `json:"target"`
		TargetType int    `json:"target_type"`
	}

	r := gin.Default()

	// create Redis client connection
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// subscribe to the Redis channel
	var pubsub *redis.PubSub

	for {
		pubsub = rdb.Subscribe("ntbuster")
		_, err := pubsub.Receive()
		if err == nil {
			break // channel exists, break out of loop
		}
		// channel does not exist, wait and try again
		time.Sleep(100 * time.Millisecond)
	}

	// create channel to receive messages
	messages := pubsub.Channel()

	// SSE endpoint to send real-time updates to the client
	r.GET("/stream", func(c *gin.Context) {
		// Set the headers for SSE
		c.Writer.Header().Set("Content-Type", "text/event-stream")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")

		// Listen for messages from Redis and send them to the client
		for msg := range messages {
			_, err := c.Writer.Write([]byte(fmt.Sprintf("data: %s\n\n", msg.Payload)))
			if err != nil {
				return
			}
			c.Writer.Flush()
		}
	})
	r.POST("/crack", func(c *gin.Context) {
		// Get the parameters from the request body
		var req CrackRequest
		err := c.BindJSON(&req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Build the command with the parameters as arguments
		var cmd *exec.Cmd
		if req.TargetType == 1 {
			cmd = exec.Command("/opt/NTbuster/bin/NTbuster", "-t", req.Target, "-u", req.Username, "-p", req.Password, "-m", "1")
		} else {
			cmd = exec.Command("/opt/NTbuster/bin/NTbuster", "-t", req.Target, "-u", req.Username, "-p", req.Password, "-m", "2")
		}
		cmd.Dir = "/Users/ch1nghz/Development/NTbuster"

		// Start the command asynchronously
		err = cmd.Start()
		if err != nil {
			// There was an error executing the command
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Return a response indicating success
		c.JSON(http.StatusOK, gin.H{"message": "Crack request received"})
	})

	r.StaticFile("/", "index.html")
	err := r.Run(":8080") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
	if err != nil {
		fmt.Println("Error starting the server:", err)
	}
}
