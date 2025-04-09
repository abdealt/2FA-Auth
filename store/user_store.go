package store

import (
	"auth/database"
	"auth/model"
	"log"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword : Hache le mot de passe avant de le stocker
func HashPassword(password string) (string, error) {
	// Génère un hash pour le mot de passe
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// GetUserByEmail : Récupère un utilisateur depuis la base de données en fonction de son email
func GetUserByEmail(email string) (*model.User, error) {
	var user model.User
	// Recherche un utilisateur avec l'email fourni
	result := database.DB.Where("email = ?", email).First(&user)
	return &user, result.Error
}

// CreateUser : Ajoute un nouvel utilisateur dans la base de données
func CreateUser(user *model.User) error {
	// Hache le mot de passe avant de le stocker
	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		log.Println("Erreur lors du hachage du mot de passe :", err)
		return err
	}

	// Remplace le mot de passe en clair par le mot de passe haché
	user.Password = hashedPassword

	// Insère l'utilisateur dans la base de données
	return database.DB.Create(user).Error
}

// CreateUsers : Ajoute un utilisateur avec un email et un mot de passe (sécurisé)
func CreateUsers(email, password string) (*model.User, error) {
	// Hache le mot de passe avant de le stocker
	hashedPassword, err := HashPassword(password)
	if err != nil {
		log.Println("Erreur lors du hachage du mot de passe :", err)
		return nil, err
	}

	// Crée l'utilisateur avec le mot de passe haché
	user := &model.User{
		Email:    email,
		Password: hashedPassword, // Stocke le mot de passe haché
	}

	// Sauvegarde l'utilisateur dans la base de données
	result := database.DB.Create(user)
	if result.Error != nil {
		log.Println("Erreur lors de la création de l'utilisateur :", result.Error)
		return nil, result.Error
	}

	return user, nil
}

// UpdateUserPassword : Met à jour le mot de passe d'un utilisateur (sécurisé)
func UpdateUserPassword(userID uint, newPassword string) error {
	var user model.User

	// Récupère l'utilisateur depuis la base de données
	if err := database.DB.First(&user, userID).Error; err != nil {
		return err
	}
	user.Password = newPassword

	return database.DB.Save(&user).Error
}

// ActivateUser : Active le compte d'un utilisateur
func ActivateUser(userID uint) error {
	// Met à jour le statut du compte utilisateur pour l'activer
	result := database.DB.Model(&model.User{}).Where("id = ?", userID).Update("active", true)
	return result.Error
}

// GetUserByID : Récupère un utilisateur depuis la base de données en fonction de son ID
func GetUserByID(id uint) (*model.User, error) {
	var user model.User
	// Recherche un utilisateur avec l'ID fourni
	result := database.DB.First(&user, id)
	return &user, result.Error
}
