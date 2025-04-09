package model

import "gorm.io/gorm"

// Modèle User : Représente un utilisateur dans la base de données
type User struct {
	gorm.Model
	Email    string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
	Active   bool   `gorm:"default:false"`
}
