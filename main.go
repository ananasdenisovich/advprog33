package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gopkg.in/gomail.v2"
)

const (
	mongoURI        = "mongodb+srv://ananasovich2002:87787276658Aa.@cluster0.80wl48q.mongodb.net/"
	databaseName    = "furnitureShopDB"
	collectionName  = "users"
	collectionName2 = "furniture"
)
const (
	smtpHost     = "smtp.gmail.com"
	smtpPort     = 587
	smtpEmail    = "ananasovich2002@gmail.com"
	smtpPassword = "zswzeyricvuquftk"
)

var client *mongo.Client
var database *mongo.Database
var usersCollection *mongo.Collection
var cartsCollection *mongo.Collection
var furnitureCollection *mongo.Collection
var logger = logrus.New()
var limiter = rate.NewLimiter(1, 3)
var jwtSecret = []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

type Picture struct {
	Large  string `json:"large" bson:"large"`
	Big    string `json:"big" bson:"big"`
	Medium string `json:"medium" bson:"medium"`
	Small  string `json:"small" bson:"small"`
}

type Furniture struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name        string             `json:"title" bson:"title"`
	Description string             `json:"description" bson:"description"`
	Price       float64            `json:"price" bson:"price"`
	Pictures    []Picture          `json:"pictures" bson:"pictures"`
	Color       string             `json:"color" bson:"color,omitempty"`
	Quantity    int                `json:"quantity"`
}
type User struct {
	ID           primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name         string             `json:"Name"`
	Email        string             `json:"Email"`
	Password     string             `json:"Password"`
	Confirmed    bool               `json:"Confirmed"`
	ConfirmToken string             `json:"ConfirmToken"`
	Roles        []string           `json:"Roles"`
	Phone        string             `json:"Phone"`
	Tariff       string             `json:"Tariff"`
	NewPassword  string             `json:"NewPassword"`
	CartID       primitive.ObjectID `json:"cartID,omitempty" bson:"cartID,omitempty"`
}

type CartItem struct {
	FurnitureID   string             `json:"furnitureID"`
	FurnitureName string             `json:"furnitureName"`
	Quantity      int                `json:"quantity"`
	Price         float64            `json:"price"`
	TotalPrice    float64            `json:"totalPrice"`
	Status        string             `json:"status"`
	UserID        primitive.ObjectID `json:"userID,omitempty" bson:"userID,omitempty"` // New field to store user ID
	CartID        primitive.ObjectID `json:"cartID,omitempty" bson:"cartID,omitempty"` // New field to store cart ID
}
type Claims struct {
	UserID primitive.ObjectID `json:"userID,omitempty" bson:"userID,omitempty"`
	Email  string             `json:"email"`
	jwt.StandardClaims
}

var carts map[string][]CartItem

func init() {
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	var err error
	client, err = mongo.NewClient(options.Client().ApplyURI(mongoURI))
	if err != nil {
		fmt.Println("Error creating MongoDB client:", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		fmt.Println("Error connecting to MongoDB:", err)
		return
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		fmt.Println("Error pinging MongoDB:", err)
		return
	}

	fmt.Println("Connected to MongoDB successfully!")

	database = client.Database(databaseName)
	usersCollection = database.Collection("users")
	cartsCollection = database.Collection("carts")
	furnitureCollection = database.Collection("furniture")
}

func AuthMiddleware(requiredRole ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Set("userID", claims["userID"].(string))
		c.Set("role", claims["role"].(string))

		if len(requiredRole) > 0 {
			userRole := claims["role"].(string)
			roleMatch := false
			for _, r := range requiredRole {
				if userRole == r {
					roleMatch = true
					break
				}
			}

			if !roleMatch {
				c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func addToCart(c *gin.Context) {
	tokenStr := c.GetHeader("Authorization")[7:] // Remove "Bearer " prefix

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var cartItem CartItem
	if err := c.BindJSON(&cartItem); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert the string representation of the furniture ID to an ObjectId
	furnitureID, err := primitive.ObjectIDFromHex(cartItem.FurnitureID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid furniture ID"})
		return
	}

	// Query the furniture item by its ObjectId
	furnitureCollection := client.Database("furnitureShopDB").Collection("furniture")
	var furniture Furniture
	err = furnitureCollection.FindOne(context.TODO(), bson.M{"_id": furnitureID}).Decode(&furniture)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Furniture item not found"})
		return
	}

	// Calculate the total price
	totalPrice := float64(furniture.Price) * float64(cartItem.Quantity)

	// Assign the total price to the cart item
	cartItem.TotalPrice = totalPrice
	cartItem.Status = "unpaid"
	cartItem.UserID = claims.UserID

	// Insert the cart item into the database
	cartsCollection := client.Database("furnitureShopDB").Collection("carts")
	result, err := cartsCollection.InsertOne(context.TODO(), cartItem)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Update the cart item with the user ID
	cartItemID := result.InsertedID.(primitive.ObjectID)
	_, err = cartsCollection.UpdateOne(
		context.TODO(),
		bson.M{"_id": cartItemID},
		bson.M{"$set": bson.M{"userID": claims.UserID, "cartID": cartItemID}}, // Set both userID and cartID
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Update the user document to include the cart ID
	userCollection := client.Database("furnitureShopDB").Collection("users")
	_, err = userCollection.UpdateOne(
		context.TODO(),
		bson.M{"email": claims.Email},
		bson.M{"$set": bson.M{"cartID": cartItemID}}, // Use the cart item ID
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return a success response with the cart ID and total price
	c.JSON(http.StatusOK, gin.H{"message": "Item added to cart successfully", "cartID": cartItemID, "totalPrice": totalPrice})
}
func getUserCarts(c *gin.Context) {
	tokenStr := c.GetHeader("Authorization")[7:] // Remove "Bearer " prefix

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	cartsCollection := client.Database("furnitureShopDB").Collection("carts")
	var userCarts []CartItem
	cursor, err := cartsCollection.Find(context.TODO(), bson.M{"userID": claims.UserID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		var cartItem CartItem
		if err = cursor.Decode(&cartItem); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		userCarts = append(userCarts, cartItem)
	}

	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, userCarts)
}

// Helper function to extract user ID from JWT token claims
func getUserIDFromToken(c *gin.Context) (primitive.ObjectID, error) {
	tokenStr := c.GetHeader("Authorization")[7:] // Remove "Bearer " prefix

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return primitive.NilObjectID, err
	}

	return claims.UserID, nil
}

func main() {
	logger := logrus.New()

	r := gin.Default()

	config := cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}

	config.AllowOrigins = []string{"http://localhost:8080"}
	r.Use(cors.New(config))
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Output: logger.Out,
		Formatter: func(params gin.LogFormatterParams) string {
			return fmt.Sprintf("{\"timestamp\":\"%s\",\"status\":%d,\"method\":\"%s\",\"path\":\"%s\"}\n",
				params.TimeStamp.Format(time.RFC3339),
				params.StatusCode,
				params.Method,
				params.Path,
			)
		},
	}))

	r.MaxMultipartMemory = 1024
	r.Use(rateLimiter(limiter))
	r.LoadHTMLGlob("templates/*")
	r.GET("/2", func(c *gin.Context) {
		c.String(http.StatusOK, "Request processed successfully")
	})

	r.POST("/logUserAction", logUserActionEndpoint)
	r.POST("/register", registerUser)
	r.POST("/login", loginUser)
	r.GET("/furniture", getFurnitures)
	r.GET("/filter", filterProductsHandler)
	r.GET("/getUser", getUserByID)
	r.POST("/submitOrder", submitOrder)
	r.PUT("/updateUser", updateUser)
	r.DELETE("/deleteUser", deleteUser)
	r.GET("/getAllUsers", getAllUsers)
	r.GET("/protected-route", AuthMiddleware(), AuthorizedHandler)
	r.GET("/confirm-user", confirmUser)
	r.GET("/users", AuthMiddleware("admin"), getUsersHandler)
	r.GET("/profile", AuthMiddleware("user"), userProfileHandler)
	r.POST("/update", AuthMiddleware("user"), updateUserHandler)
	r.POST("/cart", addToCart)
	r.GET("/user-carts", getUserCarts)

	r.Static("/static", "./static/")
	r.StaticFS("/auth", http.Dir("auth"))
	r.StaticFile("/", "index.html")

	client, err := mongo.NewClient(options.Client().ApplyURI(mongoURI))
	if err != nil {
		logger.WithError(err).Fatal("Error creating MongoDB client")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		logger.WithError(err).Fatal("Error connecting to MongoDB")
		return
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		logger.WithError(err).Fatal("Error pinging MongoDB")
		return
	}

	logger.Info("Connected to MongoDB successfully!")

	defer client.Disconnect(ctx)

	database := client.Database(databaseName)

	if err := createUsersCollection(); err != nil {
		logger.WithError(err).Fatal("Error creating users collection")
		return
	}

	if err := addAgeField(); err != nil {
		logger.WithError(err).Fatal("Error adding age field")
		return
	}
	exampleUser := User{
		Name:  "John Doe",
		Email: "john.doe@example.com",
	}

	usersCollection := database.Collection(collectionName)
	insertResult, err := usersCollection.InsertOne(ctx, exampleUser)
	if err != nil {
		logger.WithError(err).Fatal("Error inserting user")
		return
	}

	logger.Info("Inserted user with ID:", insertResult.InsertedID)
	logger.Info("Server is running on :8080...")

	if err := r.Run(":8080"); err != nil {
		logger.WithError(err).Fatal("Error starting the server")
	}
}

func AuthorizedHandler(c *gin.Context) {
	role := c.MustGet("role").(string)

	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "You are authorized"})
}

func GenerateJWTToken(userID string, role string) (string, error) {
	claims := jwt.MapClaims{
		"userID": userID,
		"role":   role,
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func filterProductsHandler(c *gin.Context) {
	color := c.Query("color")
	if color == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Url Param 'color' is missing"})
		return
	}

	var furnitureItems []Furniture
	collection := client.Database(databaseName).Collection("furniture")
	filter := bson.M{"color": color}

	cursor, err := collection.Find(context.Background(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying furniture collection"})
		return
	}
	defer cursor.Close(context.Background())

	if err = cursor.All(context.Background(), &furnitureItems); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting furniture items"})
		return
	}

	c.JSON(http.StatusOK, furnitureItems)
}
func sendEmail(to, subject, body string) error {
	from := smtpEmail
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", from, to, subject, body)

	auth := smtp.PlainAuth("", smtpEmail, smtpPassword, smtpHost)

	err := smtp.SendMail(fmt.Sprintf("%s:%d", smtpHost, smtpPort), auth, from, []string{to}, []byte(message))
	if err != nil {
		return err
	}

	return nil
}
func generateToken() string {
	tokenLength := 32
	randomBytes := make([]byte, tokenLength)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatal(err)
	}
	return base64.URLEncoding.EncodeToString(randomBytes)
}
func sendConfirmationEmail(email, confirmToken string) error {

	sender := "ananasovich2002@gmail.com"
	password := "zswzeyricvuquftk"
	smtpServer := "smtp.gmail.com"
	smtpPort := 587

	message := gomail.NewMessage()

	message.SetHeader("From", sender)

	message.SetHeader("To", email)

	message.SetHeader("Subject", "Confirmation Email")

	confirmationLink := fmt.Sprintf("http://localhost:8080/confirm-user?token=%s", confirmToken)
	message.SetBody("text/html", fmt.Sprintf("Click <a href='%s'>here</a> to confirm your registration.", confirmationLink))

	dialer := gomail.NewDialer(smtpServer, smtpPort, sender, password)

	err := dialer.DialAndSend(message)
	if err != nil {
		log.Fatal(err)
		return err
	}

	fmt.Println("Confirmation email sent successfully.")
	return nil
}

func registerUser(c *gin.Context) {
	var user User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user.Roles = []string{"user"}

	confirmToken := generateToken()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}
	user.Password = string(hashedPassword)

	user.Confirmed = false
	user.ConfirmToken = confirmToken

	usersCollection := client.Database(databaseName).Collection(collectionName)
	result, err := usersCollection.InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating user"})
		return
	}

	err = sendConfirmationEmail(user.Email, confirmToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error sending confirmation email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully. Check your email for confirmation instructions.", "userID": result.InsertedID})
}
func confirmUser(c *gin.Context) {
	token := c.Query("token")

	if token == "" {
		fmt.Println("Error: Token is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	fmt.Println("Received confirmation token:", token)

	user, err := findUserByToken(c, token)
	if err != nil {
		fmt.Println("Error finding user by token:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found with the given token"})
		return
	}

	fmt.Println("Found user:", user)

	if user.Confirmed {
		fmt.Println("Error: User is already confirmed")
		c.JSON(http.StatusBadRequest, gin.H{"error": "User is already confirmed"})
		return
	}

	err = confirmUserInDatabase(c, user.ID)
	if err != nil {
		fmt.Println("Error confirming user:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to confirm user"})
		return
	}

	fmt.Println("User confirmed successfully")

	c.HTML(http.StatusOK, "confirmation.html", gin.H{"Message": "User confirmed successfully"})
}

func findUserByToken(ctx context.Context, token string) (*User, error) {
	var user User
	err := usersCollection.FindOne(ctx, bson.M{"ConfirmToken": token}).Decode(&user)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found with token: %v", token)
		}

		return nil, err
	}

	return &user, nil
}

func confirmUserInDatabase(ctx context.Context, userID primitive.ObjectID) error {
	filter := bson.M{"_id": userID}
	update := bson.M{"$set": bson.M{"Confirmed": true, "ConfirmToken": ""}}

	_, err := usersCollection.UpdateOne(ctx, filter, update)
	return err
}

func initMongoDB() {
	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err := mongo.Connect(nil, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	client = client
	database = client.Database(databaseName)
	usersCollection = database.Collection(collectionName)
}
func updateUser(c *gin.Context) {
	var updateData struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	objID, err := primitive.ObjectIDFromHex(updateData.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	usersCollection := database.Collection(collectionName)

	var user struct {
		Email string `bson:"email"`
	}
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
		return
	}

	_, err = usersCollection.UpdateOne(
		context.Background(),
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{"name": updateData.Name, "email": updateData.Email}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user"})
		return
	}

	err = sendUpdateUserEmail(user.Email)
	if err != nil {
		fmt.Println("Error sending update user email:", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

func sendUpdateUserEmail(to string) error {
	subject := "Account Update Notification"
	body := "Your account information has been updated."
	return sendEmail(to, subject, body)
}
func updateUserHandler(c *gin.Context) {
	var updateData struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Email       string `json:"email"`
		Phone       string `json:"phone"`
		Tariff      string `json:"tariff"`
		NewPassword string `json:"newPassword"`
	}

	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	objID, err := primitive.ObjectIDFromHex(updateData.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	usersCollection := database.Collection(collectionName)
	filter := bson.M{"_id": objID}
	update := bson.M{
		"$set": bson.M{
			"name":        updateData.Name,
			"email":       updateData.Email,
			"phone":       updateData.Phone,
			"tariff":      updateData.Tariff,
			"newPassword": updateData.NewPassword,
		},
	}

	_, err = usersCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

func deleteUser(c *gin.Context) {
	userID := c.Query("id")
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	usersCollection := database.Collection(collectionName)

	var user struct {
		Email string `bson:"email"`
	}
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
		return
	}

	_, err = usersCollection.DeleteOne(context.Background(), bson.M{"_id": objID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting user"})
		return
	}

	err = sendDeleteUserEmail(user.Email)
	if err != nil {
		fmt.Println("Error sending delete user email:", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func sendDeleteUserEmail(to string) error {
	subject := "Account Deletion Notification"
	body := "Your account has been deleted."
	return sendEmail(to, subject, body)
}

func getAllUsers(c *gin.Context) {
	var users []User
	usersCollection := database.Collection(collectionName)
	cursor, err := usersCollection.Find(context.Background(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching users"})
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var user User
		cursor.Decode(&user)
		users = append(users, user)
	}

	c.JSON(http.StatusOK, users)
}
func getOrderValues(order string) int {
	switch order {
	case "asc":
		return 1
	case "desc":
		return -1
	default:
		return 1
	}
}

func getFurnitures(c *gin.Context) {
	var furniture []Furniture

	collectionName2 := client.Database(databaseName).Collection(collectionName2)

	sortParam := c.Query("sort")
	sortOrder := c.Query("order")
	minPrice := c.Query("minPrice")
	maxPrice := c.Query("maxPrice")

	page, err := strconv.Atoi(c.Query("page"))
	if err != nil || page < 1 {
		page = 1
	}

	itemsPerPage, err := strconv.Atoi(c.Query("itemsPerPage"))
	if err != nil || itemsPerPage < 1 {
		itemsPerPage = 10
	}

	options := options.Find()

	switch sortParam {
	case "title":
		options.SetSort(bson.D{{"title", getOrderValues(sortOrder)}})
	case "price":
		options.SetSort(bson.D{{"price", getOrderValues(sortOrder)}})

	}

	filter := bson.M{}
	if minPrice != "" {
		minPriceFloat, err := strconv.ParseFloat(minPrice, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid minPrice value"})
			return
		}
		filter["price"] = bson.M{"$gte": minPriceFloat}
	}
	if maxPrice != "" {
		maxPriceFloat, err := strconv.ParseFloat(maxPrice, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid maxPrice value"})
			return
		}
		if _, exists := filter["price"]; exists {
			filter["price"].(bson.M)["$lte"] = maxPriceFloat
		} else {
			filter["price"] = bson.M{"$lte": maxPriceFloat}
		}
	}

	skip := (page - 1) * itemsPerPage
	options.SetSkip(int64(skip))
	options.SetLimit(int64(itemsPerPage))

	cursor, err := collectionName2.Find(context.TODO(), filter, options)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while getting furniture data"})
		return
	}

	for cursor.Next(context.TODO()) {
		var furnitureItem Furniture
		cursor.Decode(&furnitureItem)
		furniture = append(furniture, furnitureItem)
	}

	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while getting furniture data"})
		return
	}

	c.JSON(http.StatusOK, furniture)
}

func getOrderValue(sortOrder string) {
	panic("unimplemented")
}

func handlePostOrder(w http.ResponseWriter, r *http.Request) {
	var order map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&order)
	if err != nil {
		response := map[string]string{"status": "400", "message": "Invalid JSON-message"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	fmt.Printf("Received order data: %+v\n", order)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]string{"status": "200", "message": "Order received successfully"}
	json.NewEncoder(w).Encode(response)
}

func handleHTML(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func createUsersCollection() error {
	usersCollection := database.Collection(collectionName)

	_, err := usersCollection.InsertOne(context.TODO(), User{
		Name:  "John Doe",
		Email: "john.doe@example.com",
	})

	return err
}

func getUsersHandler(c *gin.Context) {
	role := c.MustGet("role").(string)
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}

	var users []User
	usersCollection := database.Collection(collectionName)
	cursor, err := usersCollection.Find(context.Background(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching users"})
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var user User
		cursor.Decode(&user)
		users = append(users, user)
	}

	c.JSON(http.StatusOK, users)
}

func userProfileHandler(c *gin.Context) {
	userID := c.MustGet("userID").(string)

	requestedUserID := c.Param("userID")
	role := c.MustGet("role").(string)
	if role != "admin" && userID != requestedUserID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}

	switch c.Request.Method {
	case http.MethodGet:
		var user User
		usersCollection := database.Collection(collectionName)
		err := usersCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		c.JSON(http.StatusOK, user)

	case http.MethodPut:
		var updateData struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&updateData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		filter := bson.M{"_id": userID}
		update := bson.M{"$set": bson.M{"name": updateData.Name, "email": updateData.Email}}

		if updateData.Password != "" {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updateData.Password), bcrypt.DefaultCost)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
				return
			}
			update["$set"].(bson.M)["password"] = string(hashedPassword)
		}

		_, err := usersCollection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user profile"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User profile updated successfully"})
	}
}

func addAgeField() error {
	usersCollection := database.Collection(collectionName)

	_, err := usersCollection.UpdateMany(
		context.TODO(),
		bson.D{},
		bson.M{"$set": bson.M{"age": 0}},
	)

	return err
}
func logUserAction(c *gin.Context, action string, userID string) {
	logData := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"action":    action,
		"userID":    userID,
	}

	logJSON, err := json.Marshal(logData)
	if err != nil {
		fmt.Println("Error marshaling log data:", err)
		return
	}
	file, err := os.OpenFile("C:\\Users\\Asus\\Downloads\\advprog-final-main with user\\user_actions.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	defer file.Close()

	if _, err := io.WriteString(file, string(logJSON)+"\n"); err != nil {
		fmt.Println("Error writing log entry:", err)
		return
	}

	logger.WithFields(logrus.Fields{
		"timestamp": logData["timestamp"],
		"action":    logData["action"],
		"userID":    logData["userID"],
	}).Info("User action logged successfully")
}
func getUsernameFromContext(c *gin.Context) string {
	username, exists := c.Get("username")
	if !exists {
		return ""
	}
	return username.(string)
}
func logUserActionEndpoint(c *gin.Context) {
	var logData map[string]interface{}
	if err := c.ShouldBindJSON(&logData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := getUsernameFromContext(c)

	action, ok := logData["action"].(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing or invalid 'action' field"})
		return
	}
	logUserAction(c, action, userID)

	c.JSON(http.StatusOK, gin.H{"message": "User action logged successfully"})
}
func rateLimiter(limiter *rate.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !limiter.Allow() {

			resetTime := limiter.Reserve().DelayFrom(time.Now()).Round(time.Second)
			c.Header("Retry-After", fmt.Sprintf("%d", resetTime.Seconds()))
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limiter.Limit()))
			c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", 0))
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(resetTime).Unix()))
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// CRUD
func createUser(w http.ResponseWriter, r *http.Request) {
	var newUser User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	usersCollection := database.Collection(collectionName)
	insertResult, err := usersCollection.InsertOne(context.Background(), newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(insertResult)
}

// crud
func getUserByID(c *gin.Context) {
	userID := c.Query("id")
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	var user User
	usersCollection := database.Collection(collectionName)
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func loginUser(c *gin.Context) {
	var loginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	usersCollection := client.Database(databaseName).Collection(collectionName)
	var user User
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": loginRequest.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginRequest.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Set userID cookie
	c.SetCookie("userID", user.ID.Hex(), 3600, "/", "localhost", false, true)

	isAdmin := (user.Email == "admin@example.com" && user.Password == "adminpassword")

	if isAdmin {
		user.Roles = []string{"admin"}
	}

	token, err := GenerateJWTToken(user.ID.Hex(), user.Roles[0])
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating JWT token"})
		return
	}
	fmt.Println("Generated Token:", token)

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": token})
}

func submitOrder(c *gin.Context) {
	var order map[string]interface{}
	err := c.ShouldBindJSON(&order)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON-message"})
		return
	}

	fmt.Printf("Received order data: %+v\n", order)

	c.JSON(http.StatusOK, gin.H{"status": "200", "message": "Order received successfully"})
}
