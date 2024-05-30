package main

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
)

func Down_XXXXXXXXXX_create_users(ctx context.Context, client *mongo.Client) error {
	database := client.Database("furnitureShopDB")

	err := database.Collection("users").Drop(ctx)
	if err != nil {

		return fmt.Errorf("failed to drop users collection: %w", err)
	}

	return nil
}
