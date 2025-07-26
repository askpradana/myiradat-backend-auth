package configs

import (
	"fmt"
	"log"
	"sync"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	Database IDatabaseConfig
	once     sync.Once
)

type IDatabaseConfig interface {
	DbUser() *gorm.DB
}

type databaseConfig struct {
	dbUser *gorm.DB
}

func (d *databaseConfig) DbUser() *gorm.DB {
	return d.dbUser
}

var gormConfig = gorm.Config{
	Logger: logger.Default.LogMode(logger.Silent),
}

func loadConfig() (*databaseConfig, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", ""),
		getEnv("DB_NAME", ""),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_SSLMODE", "disable"),
	)

	log.Printf("Debug - DSN: %s", dsn) // Remove password from this in production

	dbUser, err := gorm.Open(postgres.Open(dsn), &gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test the connection
	sqlDB, err := dbUser.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &databaseConfig{
		dbUser: dbUser,
	}, nil
}

func NewDatabaseConfig() IDatabaseConfig {
	configDatabase, err := loadConfig()
	if err != nil {
		log.Fatalf("❌ Failed to load database config: %v", err)
	}
	return configDatabase
}

func CheckEnvDatabase() error {
	_, err := loadConfig()
	return err
}

func ReloadDatabaseConfig() {
	configDatabase, err := loadConfig()
	if err != nil {
		log.Fatalf("❌ Failed to reload database config: %v", err)
	}
	Database = configDatabase
	log.Println("✅ Database config reloaded")
}

func init() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  Warning: .env file not found, using system environment variables")
	}

	once.Do(func() {
		Database = NewDatabaseConfig()
	})
}
