package utils

import (
	"fmt"
	"net/smtp"
	"os"
)

// SendOTPEmail : Envoie un email contenant un code OTP via Gmail
func SendOTPEmail(recipient, otp string) error {
	// Récupère les identifiants Gmail depuis les variables d'environnement
	from := os.Getenv("GMAIL_USERNAME")
	password := os.Getenv("GMAIL_PASSWORD")

	// Adresse SMTP de Gmail
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Sujet et corps du message
	subject := "Votre code de vérification"
	body := fmt.Sprintf("Votre code OTP est : %s", otp)

	// Message formaté selon le protocole SMTP
	message := []byte("To: " + recipient + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")

	// Authentification SMTP
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Envoi de l'email
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{recipient}, message)
	if err != nil {
		fmt.Println("Erreur lors de l'envoi de l'email :", err)
		return err
	}

	return nil
}
