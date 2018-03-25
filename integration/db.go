package integration

import (
	"fmt"
	"log"

	"github.com/go-pg/pg"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/ory/dockertest"
)

var resources []*dockertest.Resource
var pool *dockertest.Pool

func KillAll() {
	for _, resource := range resources {
		if err := pool.Purge(resource); err != nil {
			log.Printf("Got an error while trying to purge resource: %s", err)
		}
	}
	resources = []*dockertest.Resource{}
}

func ConnectToPostgres() *pg.DB {

	var db *pg.DB
	var err error
	pool, err = dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}
	fmt.Printf("pool: %+v \n", pool)
	fmt.Printf("pool client: %+v \n", *pool.Client)

	resource, err := pool.Run("postgres", "9.6", []string{"POSTGRES_PASSWORD=secret", "POSTGRES_DB=coral"})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}
	fmt.Printf("resource: %+v \n", *resource.Container)
	if err = pool.Retry(func() error {
		var err error
		db = pg.Connect(&pg.Options{
			User:     "postgres",
			Password: "secret",
			Database: "coral",
			Addr:     fmt.Sprintf("localhost:%s", resource.GetPort("5432/tcp")),
		})
		var n int
		_, err = db.QueryOne(pg.Scan(&n), "SELECT 1")
		if err != nil {
			fmt.Println(err)
			return err
		}
		return err
	}); err != nil {
		pool.Purge(resource)
		log.Fatalf("Could not connect to docker: %s", err)
	}

	resources = append(resources, resource)
	fmt.Printf("db: %+v \n", db)
	return db
}
