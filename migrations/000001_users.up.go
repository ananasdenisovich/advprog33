package main

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func Up_XXXXXXXXXX_create_users(ctx context.Context, client *mongo.Client) error {
	database := client.Database("furnitureShopDB")

	usersCollection := database.Collection("users")

	indexModel := mongo.IndexModel{

		Keys: bson.D{{Key: "email", Value: 1}},
	}

	_, err := usersCollection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return fmt.Errorf("failed to create index on users collection: %w", err)
	}

	return nil
}
