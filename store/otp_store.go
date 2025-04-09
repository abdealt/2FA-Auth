package store

import (
	"auth/database"
	"auth/model"
	"time"
)

// CreateOTP : Enregistre un nouvel OTP dans la base de données
func CreateOTP(otp *model.OTP) error {
	return database.DB.Create(otp).Error // Utilise GORM pour insérer l'OTP
}

// GetOTPByUserID : Récupère un OTP spécifique pour un utilisateur donné
func GetOTPByUserID(userID uint, code string) (*model.OTP, error) {
	var otp model.OTP
	// Recherche un OTP correspondant à l'ID utilisateur et au code fourni
	result := database.DB.Where("user_id = ? AND code = ?", userID, code).First(&otp)
	return &otp, result.Error
}

// DeleteOTP : Supprime un OTP spécifique de la base de données
func DeleteOTP(otp *model.OTP) error {
	return database.DB.Delete(otp).Error // Utilise GORM pour supprimer l'OTP
}

// DeleteExpiredOTPs : Supprime tous les OTP expirés de la base de données
func DeleteExpiredOTPs() {
	// Supprime les OTP dont la date d'expiration est passée
	database.DB.Where("expires_at < ?", time.Now()).Delete(&model.OTP{})
}
