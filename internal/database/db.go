package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gjovanovicst/auth_api/pkg/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// ConnectDatabase establishes connection to PostgreSQL database
func ConnectDatabase() {
	// Get environment variables with validation
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbPort := os.Getenv("DB_PORT")

	// Validate required environment variables
	if dbHost == "" {
		log.Fatal("DB_HOST environment variable is required")
	}
	if dbUser == "" {
		log.Fatal("DB_USER environment variable is required")
	}
	if dbPassword == "" {
		log.Fatal("DB_PASSWORD environment variable is required")
	}
	if dbName == "" {
		log.Fatal("DB_NAME environment variable is required")
	}

	// Set default port if not specified
	if dbPort == "" {
		dbPort = "5432"
		log.Println("DB_PORT not set, defaulting to 5432")
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		dbHost,
		dbUser,
		dbPassword,
		dbName,
		dbPort,
	)

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second, // Slow SQL threshold
			LogLevel:                  logger.Info, // Log level
			IgnoreRecordNotFoundError: true,        // Ignore ErrRecordNotFound error for logger
			Colorful:                  true,        // Enable color
		},
	)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})

	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Database connected successfully!")
}

// MigrateDatabase runs GORM auto-migration for all models
func MigrateDatabase() {
	// AutoMigrate will create tables, missing columns, and missing indexes
	// It will NOT change existing column types or delete unused columns
	err := DB.AutoMigrate(
		&models.User{},
		&models.SocialAccount{},
		&models.ActivityLog{},
		&models.SchemaMigration{}, // Migration tracking table
	)

	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	log.Println("Database migration completed!")
}
