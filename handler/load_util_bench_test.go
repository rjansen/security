package handler

import (
	"bytes"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/client/cassandra"
	"farm.e-pedion.com/repo/security/config"
	"farm.e-pedion.com/repo/security/data"
	"github.com/gocql/gocql"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"strconv"
	"testing"
)

func BenchmarkGetTestHandler(b *testing.B) {
	logSetupErr := logger.Setup(logger.Configuration{
		Provider: logger.LOGRUS,
		Level:    logger.DEBUG,
		Out:      logger.Out("./security.bench.log"),
	})
	if logSetupErr != nil {
		panic(logSetupErr)
	}
	log = logger.GetLogger()
	assert.Nil(b, cassandra.Setup(config.CassandraConfig{
		URL:      "127.0.0.1:9042",
		Keyspace: "fivecolors",
		Username: "fivecolors",
		Password: "fivecolors",
	}))
	testHandler := NewLoadTestHandler()

	var times int
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var ctx fasthttp.RequestCtx
		var req fasthttp.Request
		for pb.Next() {
			times++
			// username := "user" + strconv.Itoa(times)
			username := "darkside"
			req.SetRequestURI("http://test/" + username)
			ctx.Init(&req, nil, nil)

			testHandler.Get.HandleRequest(&ctx)

			assert.NotEmpty(b, ctx.Response.Body())
			assert.True(b, bytes.Contains(ctx.Response.Body(), []byte(username)))
			assert.Equal(b, ctx.Response.StatusCode(), fasthttp.StatusOK)
		}
	})
}

func BenchmarkPostTestHandler(b *testing.B) {
	log = logger.NewLoggerByConfig(logger.Configuration{Level: logger.ERROR, Out: logger.DISCARD})
	testHandler := NewLoadTestHandler()

	var times int
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var ctx fasthttp.RequestCtx
		var req fasthttp.Request
		for pb.Next() {
			times++
			username := "user" + strconv.Itoa(times)
			req.SetRequestURI("http://test/")
			req.SetBody([]byte(`{"username": "` + username + `"}`))
			ctx.Init(&req, nil, nil)

			testHandler.Post.HandleRequest(&ctx)

			assert.NotEmpty(b, ctx.Response.Body())
			assert.True(b, bytes.Contains(ctx.Response.Body(), []byte(username)))
			assert.Equal(b, ctx.Response.StatusCode(), fasthttp.StatusCreated)
		}
	})
}

func BenchmarkCassandraRead(b *testing.B) {
	logSetupErr := logger.Setup(logger.Configuration{
		Provider: logger.LOGRUS,
		Level:    logger.DEBUG,
		Out:      logger.Out("./security.bench.log"),
	})
	if logSetupErr != nil {
		panic(logSetupErr)
	}
	log = logger.GetLogger()
	config := config.CassandraConfig{
		URL:      "127.0.0.1:9042",
		Keyspace: "fivecolors_test",
		Username: "fivecolors_test",
		Password: "fivecolors_test",
	}
	cluster := gocql.NewCluster(config.URL)
	cluster.NumConns = 5
	cluster.ProtoVersion = 4
	cluster.Keyspace = config.Keyspace
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: config.Username,
		Password: config.Password,
	}

	session, err := cluster.CreateSession()
	assert.Nil(b, err)
	assert.NotNil(b, session)

	var times int
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			times++

			username := "makefile1"
			cql := `select username, name, password, roles from login where username = ? limit`
			query := session.Query(cql, username).Consistency(gocql.One)
			var login data.Login
			fetchErr := login.Fetch(query)
			assert.Nil(b, fetchErr)

			assert.NotZero(b, login.Username)
			assert.Equal(b, login.Username, username)
			assert.NotZero(b, login.Name)
			assert.NotZero(b, login.Password)
			assert.NotZero(b, login.Password)
		}
	})
}

func BenchmarkMongoRead(b *testing.B) {
	logSetupErr := logger.Setup(logger.Configuration{
		Provider: logger.LOGRUS,
		Level:    logger.DEBUG,
		Out:      logger.Out("./security.bench.log"),
	})
	if logSetupErr != nil {
		panic(logSetupErr)
	}
	log = logger.GetLogger()

	config := config.MongoConfig{
		URL:      "127.0.0.1:27017",
		Database: "fivecolors_test",
		Username: "fivecolors_test",
		Password: "fivecolors_test",
	}
	session, dialErr := mgo.DialWithInfo(&mgo.DialInfo{
		Addrs:    []string{config.URL},
		Database: config.Database,
		Username: config.Username,
		Password: config.Password,
	})
	assert.Nil(b, dialErr)

	var times int
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			times++

			s := session.Copy()
			collection := s.DB(config.Database).C("login")
			assert.NotNil(b, collection)
			username := "makefile1"
			var login data.Login
			findErr := collection.Find(bson.M{"username": username}).One(&login)
			s.Close()
			assert.Nil(b, findErr)

			assert.NotZero(b, login.Username)
			assert.Equal(b, login.Username, username)
			assert.NotZero(b, login.Name)
			assert.NotZero(b, login.Password)
			assert.NotZero(b, login.Password)
		}
	})
}
