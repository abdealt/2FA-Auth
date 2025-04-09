package app

import (
	"fmt"
	"log"

	"auth/database"
	"auth/route"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"
)

var sessionStore *session.Store

func Run() {
	// Charger la connexion à la BDD
	database.Connect()

	// Configuration du moteur de vues (templates HTML)
	engine := html.New("./views", ".html")
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// Initialiser le store de session
	sessionStore = session.New()

	// Middleware pour attacher la session à chaque requête
	app.Use(func(c *fiber.Ctx) error {
		// Récupère l'instance de session pour cette requête
		sess, err := sessionStore.Get(c)
		if err != nil {
			return err
		}
		c.Locals("session", sess)
		return c.Next()
	})

	// Configuration des routes
	route.SetupRoutes(app)

	// Démarrage du serveur
	fmt.Println("Page de connexion http://localhost:3000/login")
	log.Fatal(app.Listen(":3000"))
}
