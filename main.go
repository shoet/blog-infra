package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/upstash/pulumi-upstash/sdk/go/upstash"
)

var projectTag = "blog"

func main() {
	config, err := NewConfig()
	if err != nil {
		log.Fatalf("error loading config: %v", err)
	}

	pulumi.Run(func(ctx *pulumi.Context) error {
		// AccountID ///////////////////////////////////////////////////////////////////
		caller, err := aws.GetCallerIdentity(ctx, nil, nil)
		if err != nil {
			return err
		}
		accountId := caller.AccountId

		// S3 ////////////////////////////////////////////////////////////////////////
		// bucket app ------------------------------------------------
		resourceName := fmt.Sprintf("%s-s3-bucket-app", projectTag)
		bucketNameApp := fmt.Sprintf("blog-%s-app", accountId)
		s3BucketApp, err := s3.NewBucket(
			ctx,
			resourceName,
			&s3.BucketArgs{
				Bucket: pulumi.String(bucketNameApp),
				Acl:    pulumi.String("private"),
			},
		)
		if err != nil {
			return err
		}
		ctx.Export(resourceName, s3BucketApp.ID())

		// bucket thumbnail ------------------------------------------------
		resourceName = fmt.Sprintf("%s-s3-bucket", projectTag)
		bucketName := fmt.Sprintf("blog-%s", accountId)
		s3Bucket, err := s3.NewBucket(
			ctx,
			resourceName,
			&s3.BucketArgs{
				Bucket: pulumi.String(bucketName),
			},
		)
		if err != nil {
			return err
		}
		ctx.Export(resourceName, s3Bucket.ID())

		// Bucket OwnerShip
		resourceName = fmt.Sprintf("%s-s3-ownership", projectTag)
		bucketOwnership, err := s3.NewBucketOwnershipControls(
			ctx,
			resourceName,
			&s3.BucketOwnershipControlsArgs{
				Bucket: s3Bucket.ID(),
				Rule: &s3.BucketOwnershipControlsRuleArgs{
					ObjectOwnership: pulumi.String("BucketOwnerPreferred"),
				},
			})
		if err != nil {
			return err
		}
		ctx.Export(resourceName, bucketOwnership.ID())

		// CORS Configuration
		// フロントでのPreFlightリクエストを許可する
		whiteList := config.GetCORSWhiteList()
		var corsWhiteList pulumi.StringArray
		for _, w := range whiteList {
			corsWhiteList = append(corsWhiteList, pulumi.String(w))
		}
		resourceName = fmt.Sprintf("%s-s3-cors", projectTag)
		s3CORS, err := s3.NewBucketCorsConfigurationV2(
			ctx,
			resourceName,
			&s3.BucketCorsConfigurationV2Args{
				Bucket: s3Bucket.ID(),
				CorsRules: s3.BucketCorsConfigurationV2CorsRuleArray{
					&s3.BucketCorsConfigurationV2CorsRuleArgs{
						AllowedHeaders: pulumi.StringArray{
							pulumi.String("*"),
						},
						AllowedMethods: pulumi.StringArray{
							pulumi.String("PUT"),
						},
						AllowedOrigins: corsWhiteList,
						MaxAgeSeconds:  pulumi.Int(3000),
					},
				},
			})
		if err != nil {
			return err
		}
		ctx.Export(resourceName, s3CORS.ID())

		// Public Access Block
		resourceName = fmt.Sprintf("%s-s3-public_access_block", projectTag)
		publicAccessBlock, err := s3.NewBucketPublicAccessBlock(
			ctx,
			resourceName,
			&s3.BucketPublicAccessBlockArgs{
				Bucket:                s3Bucket.ID(),
				BlockPublicAcls:       pulumi.Bool(false),
				BlockPublicPolicy:     pulumi.Bool(false),
				IgnorePublicAcls:      pulumi.Bool(false),
				RestrictPublicBuckets: pulumi.Bool(false),
			})
		if err != nil {
			return err
		}
		ctx.Export(resourceName, publicAccessBlock.ID())

		// Policy
		// thumbnail配下のオブジェクトに対してGetObjectを許可する
		resourceName = fmt.Sprintf("%s-s3-bucket_policy", projectTag)
		bucketPolicy, err := s3.NewBucketPolicy(
			ctx,
			resourceName,
			&s3.BucketPolicyArgs{
				Bucket: s3Bucket.ID(), // refer to the bucket created earlier
				Policy: pulumi.Any(map[string]interface{}{
					"Version": "2012-10-17",
					"Statement": []map[string]interface{}{
						{
							"Effect":    "Allow",
							"Principal": "*",
							"Action": []interface{}{
								"s3:GetObject",
							},
							"Resource": []interface{}{
								pulumi.Sprintf("arn:aws:s3:::%s/thumbnail/*", s3Bucket.ID()),
								pulumi.Sprintf("arn:aws:s3:::%s/content/*", s3Bucket.ID()),
							},
						},
					},
				}),
			},
			pulumi.DependsOn(
				[]pulumi.Resource{
					s3Bucket,
					publicAccessBlock,
					bucketOwnership,
				},
			),
		)
		if err != nil {
			return err
		}
		ctx.Export(resourceName, bucketPolicy.ID())

		// KVS upstash (Redis) /////////////////////////////////////////////////
		resourceName = fmt.Sprintf("%s-kvs-redis-by-upstash", projectTag)
		redisKVS, err := upstash.NewRedisDatabase(ctx, resourceName, &upstash.RedisDatabaseArgs{
			DatabaseName: pulumi.String("blog-kvs"),
			Region:       pulumi.String("ap-northeast-1"),
			Tls:          pulumi.Bool(true),
			Eviction:     pulumi.Bool(true),
		})
		if err != nil {
			fmt.Println(err)
			return err
		}
		ctx.Export(resourceName, redisKVS.ID())

		return nil

	})
}

func createNameTag(tag string) pulumi.StringMap {
	return pulumi.StringMap{
		"Name": pulumi.String(tag),
	}
}

func loadFileToString(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed open file: %v", err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("failed read file: %v", err)
	}
	return string(b), nil
}
