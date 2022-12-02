package repo

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Find executes a find command and returns a Cursor over the matching documents in the collection
func Find[T any](collection *mongo.Collection, filter any, opt ...*options.FindOptions) ([]*T, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cur, err := collection.Find(ctx, filter, opt...)
	if err != nil {
		log.Err(err).Msg("Error find all users")
		return nil, err
	}

	defer func() {
		_ = cur.Close(ctx)
	}()

	var data []*T
	for cur.Next(ctx) {
		obj := new(T)
		if err = cur.Decode(obj); err != nil {
			log.Err(err).Msg("Error find all")
			return nil, err
		}

		data = append(data, obj)
	}

	return data, nil
}

// CountDocuments returns the number of documents in the collection. For a fast count of the documents in the collection, see the EstimatedDocumentCount method
func CountDocuments(collection *mongo.Collection, filter any) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		log.Err(err).Msg("Error count all")
		return 0, err
	}

	return total, nil
}

// FindOne executes a find command and returns a SingleResult for one document in the collection
func FindOne[T any](collection *mongo.Collection, filter any, opt ...*options.FindOneOptions) (
	*T, error,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := new(T)
	err := collection.FindOne(ctx, filter, opt...).Decode(result)
	if err != nil {
		log.Err(err).Msg("Error find")
		return nil, err
	}

	return result, nil
}

// FindOneAndUpdate executes a findAndModify command to update at most one document in the collection and returns the document as it appeared before updating
func FindOneAndUpdate(collection *mongo.Collection, filter, data any, opt ...*options.FindOneAndUpdateOptions) (
	*mongo.SingleResult, error,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := new(mongo.SingleResult)
	err := collection.FindOneAndUpdate(ctx, filter, data, opt...).Decode(result)
	if err != nil {
		log.Err(err).Msg("Error find one and update")
		return nil, err
	}

	return result, nil
}

// InsertOne executes an insert command to insert a single document into the collection
func InsertOne(collection *mongo.Collection, data any, opt ...*options.InsertOneOptions) (
	*mongo.InsertOneResult, error,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := collection.InsertOne(ctx, data, opt...)
	if err != nil {
		log.Err(err).Msg("Error create one")
		return nil, err
	}

	return res, nil
}

// InsertMany executes an insert command to insert multiple documents into the collection. If write errors occur during the operation (e.g. duplicate key error), this method returns a BulkWriteException error
func InsertMany(collection *mongo.Collection, data []any, opt ...*options.InsertManyOptions) (
	*mongo.InsertManyResult, error,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := collection.InsertMany(ctx, data, opt...)
	if err != nil {
		log.Err(err).Msg("Error insert many")
		return nil, err
	}

	return res, nil
}

// UpdateOne executes an update command to update at most one document in the collection
func UpdateOne(collection *mongo.Collection, filter, data any, opt ...*options.UpdateOptions) (
	*mongo.UpdateResult, error,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := collection.UpdateOne(ctx, filter, data, opt...)
	if err != nil {
		log.Err(err).Msg("Error update one")
		return nil, err
	}

	return res, nil
}

// UpdateMany executes an update command to update documents in the collection
func UpdateMany(collection *mongo.Collection, filter, data any, opt ...*options.UpdateOptions) (
	*mongo.UpdateResult, error,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := collection.UpdateMany(ctx, filter, data, opt...)
	if err != nil {
		log.Err(err).Msg("Error update many")
		return nil, err
	}

	return res, nil
}

// DeleteOne executes a delete command to delete at most one document from the collection
func DeleteOne(collection *mongo.Collection, filter any, opt ...*options.DeleteOptions) (
	*mongo.DeleteResult, error,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := collection.DeleteOne(ctx, filter, opt...)
	if err != nil {
		log.Err(err).Msg("Error delete one")
		return nil, err
	}

	return res, nil
}

// DeleteMany executes a delete command to delete documents from the collection
func DeleteMany(collection *mongo.Collection, filter any, opt ...*options.DeleteOptions) (
	*mongo.DeleteResult, error,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := collection.DeleteMany(ctx, filter, opt...)
	if err != nil {
		log.Err(err).Msg("Error delete many")
		return nil, err
	}

	return res, nil
}

// SoftDeleteOne soft deletes one
func SoftDeleteOne(collection *mongo.Collection, filter any, opt ...*options.UpdateOptions) (
	*mongo.UpdateResult, error,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	data := bson.M{
		"$set": bson.D{
			{
				"deleted_at",
				time.Now(),
			},
		},
	}
	res, err := collection.UpdateOne(ctx, filter, data, opt...)
	if err != nil {
		log.Err(err).Msg("Error soft delete one")
		return nil, err
	}

	return res, nil
}
