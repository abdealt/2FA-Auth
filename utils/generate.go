package utils

import (
	"encoding/hex"
	"math/rand"
	"strconv"
	"time"
)

// GenerateOTP : Génère un code OTP (One-Time Password) aléatoire à 6 chiffres
func GenerateOTP() string {
	// Initialise la graine du générateur de nombres aléatoires avec l'heure actuelle
	rand.Seed(time.Now().UnixNano())

	// Génère un nombre aléatoire entre 100000 et 999999 (6 chiffres)
	otp := rand.Intn(900000) + 100000

	// Convertit le nombre en chaîne de caractères et le retourne
	return strconv.Itoa(otp)
}

// Fonction generateResetToken : Génère un token aléatoire pour la réinitialisation du mot de passe
func GenerateResetToken() (string, error) {
	b := make([]byte, 16) // 16 octets = 32 caractères hexadécimaux
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
