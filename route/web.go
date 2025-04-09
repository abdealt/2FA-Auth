package route

import (
	"auth/handlers"
	"auth/middleware"

	"github.com/gofiber/fiber/v2"
)

// SetupRoutes configure les routes de l'application
func SetupRoutes(app *fiber.App) {
	// Routes publiques (pas besoin de middleware)
	// Route d'affichage du formulaire de login
	app.Get("/login", handlers.ShowLogin)
	app.Get("/", handlers.ShowLogin) // Redirection vers la page de login par défaut

	// Soumission du formulaire de login
	app.Post("/login", handlers.Login)

	// Route pour se deconnecter
	app.Get("/logout", handlers.Logout)

	// Vérification de l'OTP (One-Time Password)
	app.Post("/verifyotp", handlers.VerifyOTP)

	// Routes pour "Mot de passe oublié"
	// Affiche le formulaire pour demander un lien de réinitialisation de mot de passe
	app.Get("/forgot-password", handlers.ShowForgotPassword)

	// Soumission du formulaire "Mot de passe oublié"
	app.Post("/forgot-password", handlers.ForgotPassword)

	// Affiche le formulaire pour réinitialiser le mot de passe
	app.Get("/reset-password", handlers.ShowResetPassword)

	// Soumission du formulaire pour réinitialiser le mot de passe
	app.Post("/reset-password", handlers.ResetPassword)

	// Route pour l'affichage du formulaire d'inscription
	app.Get("/register", handlers.ShowRegister)

	// Soumission du formulaire d'inscription
	app.Post("/register", handlers.Register)

	// Route pour l'activation du compte
	app.Post("/activate", handlers.ActivateAccount)

	// Routes protégées (nécessitent une authentification)
	// Groupe de routes protégées
	protected := app.Group("/", middleware.AuthMiddleware())

	// Dashboard (page protégée, nécessite une vérification de session/authentification)
	protected.Get("/dashboard", handlers.Dashboard)
}
