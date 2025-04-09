package handlers

import (
	"time"

	"auth/model"
	"auth/store"
	"auth/utils"

	"golang.org/x/crypto/bcrypt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

// Fonction pour comparer les mots de passe
func checkPasswordHash(storedPassword, inputPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
	return err == nil
}

// Fonction Login : Gère la connexion de l'utilisateur
func Login(c *fiber.Ctx) error {
	email := c.FormValue("email")       // Récupère l'email depuis le formulaire
	password := c.FormValue("password") // Récupère le mot de passe depuis le formulaire

	// Vérifie si l'utilisateur existe dans la base de données
	user, err := store.GetUserByEmail(email)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Utilisateur non trouvé")
	}

	// Vérifie si le compte est actif
	if !user.Active {
		return c.Status(fiber.StatusUnauthorized).SendString("Veuillez activer votre compte")
	}

	// Vérifie si le mot de passe est correct
	if !checkPasswordHash(user.Password, password) {
		return c.Status(fiber.StatusUnauthorized).SendString("Mot de passe incorrect")
	}

	// Génère un OTP (One-Time Password) et l'enregistre dans la base de données
	otpCode := utils.GenerateOTP()
	otp := &model.OTP{
		Code:      otpCode,
		ExpiresAt: time.Now().Add(5 * time.Minute), // L'OTP expire après 5 minutes
		UserID:    user.ID,
	}
	if err := store.CreateOTP(otp); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Erreur lors de la création de l'OTP")
	}

	// Envoie l'OTP par email à l'utilisateur
	if err := utils.SendOTPEmail(user.Email, otpCode); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Erreur lors de l'envoi de l'OTP")
	}

	// Stocke l'ID utilisateur dans la session
	sess := c.Locals("session").(*session.Session)
	sess.Set("user_id", user.ID)
	sess.Save()

	// Redirige vers la page de vérification OTP
	return c.Render("verifyotp", fiber.Map{
		"Email": user.Email,
	})
}

// Fonction ShowLogin : Affiche la page de connexion
func ShowLogin(c *fiber.Ctx) error {
	// Récupère les paramètres de requête pour les messages
	errorParam := c.Query("error")
	statusParam := c.Query("status")

	// Prépare les données pour le template
	data := fiber.Map{}

	if errorParam != "" {
		data["error"] = errorParam
	}

	if statusParam != "" {
		data["status"] = statusParam
	}

	return c.Render("login", data)
}

// Fonction VerifyOTP : Vérifie le code OTP saisi par l'utilisateur
func VerifyOTP(c *fiber.Ctx) error {
	code := c.FormValue("otp") // Récupère le code OTP depuis le formulaire

	// Récupère l'ID utilisateur depuis la session
	session := c.Locals("session").(*session.Session)
	userID := session.Get("user_id")
	if userID == nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Session invalide")
	}

	// Vérifie si l'OTP est valide
	otp, err := store.GetOTPByUserID(userID.(uint), code)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Code invalide")
	}

	// Vérifie si l'OTP a expiré
	if time.Now().After(otp.ExpiresAt) {
		return c.Status(fiber.StatusUnauthorized).SendString("Code expiré")
	}

	// Supprime l'OTP après validation (optionnel)
	store.DeleteOTP(otp)

	// Redirige l'utilisateur vers le tableau de bord après une authentification réussie
	return c.Redirect("/dashboard")
}

// Fonction Dashboard : Affiche le tableau de bord après connexion
func Dashboard(c *fiber.Ctx) error {
	return c.Render("dashboard", fiber.Map{
		"Message": "Bienvenue sur le Dashboard!",
	})
}

// Fonction Logout : Déconnecte l'utilisateur
func Logout(c *fiber.Ctx) error {
	// Récupère la session
	session := c.Locals("session").(*session.Session)
	// Supprime la session
	session.Destroy()

	// Redirige l'utilisateur vers la page de connexion
	return c.Redirect("/login?status=logout_success")
}

// Fonction ShowForgotPassword : Affiche le formulaire pour demander un lien de réinitialisation de mot de passe
func ShowForgotPassword(c *fiber.Ctx) error {
	return c.Render("forgot_password", nil)
}

// Fonction ForgotPassword : Gère la soumission du formulaire "Mot de passe oublié"
func ForgotPassword(c *fiber.Ctx) error {
	email := c.FormValue("email") // Récupère l'email depuis le formulaire

	// Vérifie si l'utilisateur existe
	user, err := store.GetUserByEmail(email)
	if err != nil {
		// Pour des raisons de sécurité, ne pas révéler qu'un email est inconnu
		return c.SendString("Si cet email existe, un lien de réinitialisation vous sera envoyé.")
	}

	// Génère un token de réinitialisation
	token, err := utils.GenerateResetToken()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Erreur lors de la génération du token")
	}

	// Stocke temporairement le token et l'ID utilisateur dans la session
	sess := c.Locals("session").(*session.Session)
	sess.Set("reset_token", token)
	sess.Set("reset_user_id", user.ID)
	sess.Save()

	// Envoie un email avec le lien de réinitialisation
	resetLink := c.BaseURL() + "/reset-password?token=" + token
	emailBody := "Cliquez sur le lien suivant pour réinitialiser votre mot de passe : " + resetLink

	if err := utils.SendOTPEmail(user.Email, emailBody); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Erreur lors de l'envoi de l'email")
	}

	return c.Redirect("/login?status=forgot_password")
}

// Fonction ShowResetPassword : Affiche le formulaire pour réinitialiser le mot de passe
func ShowResetPassword(c *fiber.Ctx) error {
	token := c.Query("token") // Récupère le token depuis l'URL
	sess := c.Locals("session").(*session.Session)
	storedToken := sess.Get("reset_token")

	if storedToken == nil || storedToken != token {
		return c.Status(fiber.StatusUnauthorized).SendString("Token invalide ou expiré")
	}

	return c.Render("reset_password", fiber.Map{
		"Token": token,
	})
}

// Fonction ResetPassword : Gère la réinitialisation du mot de passe
func ResetPassword(c *fiber.Ctx) error {
	token := c.FormValue("token")          // Récupère le token depuis le formulaire
	newPassword := c.FormValue("password") // Récupère le nouveau mot de passe

	sess := c.Locals("session").(*session.Session)
	storedToken := sess.Get("reset_token")
	userID := sess.Get("reset_user_id")

	if storedToken == nil || storedToken != token {
		return c.Status(fiber.StatusUnauthorized).SendString("Token invalide ou expiré")
	}

	if userID == nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Session invalide")
	}

	// Hache le nouveau mot de passe avant de le stocker
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Erreur lors du hachage du mot de passe")
	}

	// Met à jour le mot de passe de l'utilisateur
	err = store.UpdateUserPassword(userID.(uint), string(hashedPassword))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Erreur lors de la mise à jour du mot de passe")
	}

	// Supprime les données de réinitialisation de la session
	sess.Delete("reset_token")
	sess.Delete("reset_user_id")
	sess.Save()

	return c.Redirect("/login?status=password_reset")
}

// Fonction ShowRegister : Affiche le formulaire d'inscription
func ShowRegister(c *fiber.Ctx) error {
	return c.Render("register", nil)
}

// Fonction Register : Gère l'inscription d'un nouvel utilisateur
func Register(c *fiber.Ctx) error {
	// Récupère les données du formulaire
	email := c.FormValue("email")
	password := c.FormValue("password")
	confirmPassword := c.FormValue("confirm_password")

	// Vérifie que les mots de passe correspondent
	if password != confirmPassword {
		return c.Status(fiber.StatusBadRequest).SendString("Les mots de passe ne correspondent pas")
	}

	// Vérifie si l'utilisateur existe déjà
	_, err := store.GetUserByEmail(email)
	if err == nil {
		// Un utilisateur avec cet email existe déjà
		return c.Status(fiber.StatusConflict).SendString("Un compte avec cet email existe déjà")
	}

	// Crée un nouvel utilisateur avec le statut inactif
	user := &model.User{
		Email:    email,
		Password: password, // Le mot de passe sera haché dans CreateUser
		Active:   false,    // L'utilisateur est inactif jusqu'à la validation de l'OTP
	}

	// Enregistre l'utilisateur dans la base de données
	if err := store.CreateUser(user); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Erreur lors de la création du compte")
	}

	// Génère un OTP pour la vérification de l'email
	otpCode := utils.GenerateOTP()
	otp := &model.OTP{
		Code:      otpCode,
		ExpiresAt: time.Now().Add(15 * time.Minute), // L'OTP expire après 15 minutes
		UserID:    user.ID,
	}

	// Enregistre l'OTP dans la base de données
	if err := store.CreateOTP(otp); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Erreur lors de la création de l'OTP")
	}

	// Envoie l'OTP par email à l'utilisateur
	if err := utils.SendOTPEmail(user.Email, otpCode); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Erreur lors de l'envoi de l'OTP")
	}

	// Stocke l'ID utilisateur dans la session
	sess := c.Locals("session").(*session.Session)
	sess.Set("user_id", user.ID)
	sess.Save()

	// Redirige vers la page de vérification OTP avec un message spécifique pour l'inscription
	return c.Render("activate_account", fiber.Map{
		"Email":   user.Email,
		"Message": "Votre compte a été créé. Veuillez saisir le code OTP envoyé à votre adresse email pour activer votre compte.",
	})
}

// Fonction ActivateAccount : Active le compte utilisateur après vérification OTP
func ActivateAccount(c *fiber.Ctx) error {
	code := c.FormValue("otp") // Récupère le code OTP depuis le formulaire

	// Récupère l'ID utilisateur depuis la session
	session := c.Locals("session").(*session.Session)
	userID := session.Get("user_id")
	if userID == nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Session invalide")
	}

	// Vérifie si l'OTP est valide
	otp, err := store.GetOTPByUserID(userID.(uint), code)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Code invalide")
	}

	// Vérifie si l'OTP a expiré
	if time.Now().After(otp.ExpiresAt) {
		return c.Status(fiber.StatusUnauthorized).SendString("Code expiré")
	}

	// Active le compte utilisateur
	err = store.ActivateUser(userID.(uint))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Erreur lors de l'activation du compte")
	}

	// Supprime l'OTP après validation
	store.DeleteOTP(otp)

	// Redirige l'utilisateur vers la page de connexion avec un message de succès
	return c.Redirect("/login?status=account_activated")
}
