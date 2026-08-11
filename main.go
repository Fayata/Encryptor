package main

import (
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "encryptor/db"
    "encryptor/server"
)

func main() {
    database, err := db.InitDB("")
    if err != nil {
        fmt.Printf("Database error: %v\n", err)
        os.Exit(1)
    }
    defer database.Close()

    srv, err := server.NewServer(database, "8080")
    if err != nil {
        fmt.Printf("Server error: %v\n", err)
        os.Exit(1)
    }
    srv.Start()

    fmt.Println("Faycryptor API server running on http://localhost:8080")

    // Block until SIGINT/SIGTERM
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    fmt.Println("\nShutting down...")
}
