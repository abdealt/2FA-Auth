package model

import (
	"time"

	"gorm.io/gorm"
)

// Modèle OTP : Représente un code OTP (One-Time Password) dans la base de données
type OTP struct {
	gorm.Model           // Fournit des champs intégrés comme ID, CreatedAt, UpdatedAt, DeletedAt
	Code       string    // Le code OTP généré pour l'utilisateur
	ExpiresAt  time.Time // La date et l'heure d'expiration du code OTP
	UserID     uint      // L'ID de l'utilisateur associé à ce code OTP (clé étrangère)
}
