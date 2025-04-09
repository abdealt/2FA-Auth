package middleware

import (
	"auth/store"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

// AuthMiddleware vérifie si l'utilisateur est authentifié
func AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Récupère la session
		sess := c.Locals("session").(*session.Session)
		userID := sess.Get("user_id")

		// Vérifie si l'ID utilisateur existe dans la session
		if userID == nil {
			// Utilisateur non connecté, redirection vers la page de connexion
			return c.Redirect("/login?error=auth_required")
		}

		// Récupère les informations de l'utilisateur
		user, err := store.GetUserByID(userID.(uint))
		if err != nil {
			// Utilisateur non trouvé, supprime la session et redirige
			sess.Destroy()
			return c.Redirect("/login?error=invalid_session")
		}

		// Temporairement désactivé pour le débogage
		/*
		   // Vérifie si le compte est actif
		   if !user.Active {
		       // Compte inactif, redirige vers la page de connexion
		       return c.Redirect("/login?error=inactive_account")
		   }
		*/

		// Stocke l'utilisateur dans les contextes locaux pour une utilisation ultérieure
		c.Locals("user", user)

		// Continue vers le gestionnaire suivant
		return c.Next()
	}
}
