package database

import (
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres" // Pilote PostgreSQL pour GORM
	"gorm.io/gorm"            // ORM pour interagir avec la base de données

	"auth/model" // Importation des modèles User et OTP

	"github.com/joho/godotenv" // Bibliothèque pour charger les variables d'environnement depuis un fichier .env
)

// DB est une variable globale qui représente la connexion à la base de données
var DB *gorm.DB

// Connect initialise la connexion à la base de données PostgreSQL
func Connect() {
	// Chargement des variables d'environnement depuis le fichier .env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Erreur lors du chargement du fichier .env") // Arrête le programme si le fichier .env est introuvable
	}

	// Récupération des variables d'environnement nécessaires pour la connexion
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	// Construction de la chaîne de connexion (DSN : Data Source Name)
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	// Ouverture de la connexion à la base de données avec GORM
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Erreur de connexion à la base de données : ", err) // Arrête le programme si la connexion échoue
	}

	// Migration automatique des modèles User et OTP dans la base de données
	DB.AutoMigrate(&model.User{}, &model.OTP{})
}
