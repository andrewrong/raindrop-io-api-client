package raindrop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func Test_NewClient(t *testing.T) {
	actual, err := NewClient("test_id", "test_secret",
		"test_redirect_uri")
	if err != nil {
		t.Errorf("error: %v", err)
	}

	accessToken := "access-token"
	actualURL := actual.apiURL.String()
	expectedURL := "https://api.raindrop.io"
	if actualURL != expectedURL {
		t.Errorf("assert failed. expect:%s actual:%s", expectedURL, actualURL)
	}

	actualAccessToken := accessToken
	expectedAccessToken := "access-token"
	if actualURL != expectedURL {
		t.Errorf("assert failed. expect:%s actual:%s",
			expectedAccessToken, actualAccessToken)
	}
}

func TestClient_GetAuthorizationURL(t *testing.T) {
	client, err := NewClient("test_id", "test_secret",
		"test_redirect_uri")
	if err != nil {
		t.Errorf("error: %v", err)
	}

	auth, err := client.GetAuthorizationURL()
	if err != nil {
		t.Errorf("error: %v", err)
	}

	actualAuthUrl, err := url.QueryUnescape(auth.String())
	if err != nil {
		t.Errorf("error: %v", err)
	}

	expectedAuthUrl :=
		"https://raindrop.io/oauth/authorize?client_id=test_id&redirect_uri=test_redirect_uri"

	if actualAuthUrl != expectedAuthUrl {
		t.Errorf("assert failed. expect:%s actual:%s", expectedAuthUrl, actualAuthUrl)
	}
}

func Test_GetRaindrops(t *testing.T) {
	// Given
	raindrop1 := Raindrop{
		RaindropUserInfo: RaindropUserInfo{
			Tags:  []string{"foo", "bar"},
			Title: "Test 1",
			Link:  "https://example.com/1",
		},
	}
	raindrop2 := Raindrop{
		RaindropUserInfo: RaindropUserInfo{
			Tags:  []string{"baz"},
			Title: "Test 2",
			Link:  "https://example.com/2",
		},
	}
	expected := MultiRaindropsResponse{
		Result: true,
		Items:  []Raindrop{raindrop1, raindrop2},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := json.Marshal(expected)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(res)
	}))

	defer ts.Close()

	// When
	sut := createTestClient(ts, t)

	// Then
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	actual, err := sut.GetRaindrops("access-token", "1", 50, ctx)
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if actual.Result != true {
		t.Error("actual.Result")
	}
	if len(actual.Items) != 2 {
		t.Errorf("Unexpected length: %d", len(actual.Items))
	}
	if !reflect.DeepEqual(actual.Items[0], raindrop1) {
		t.Errorf("Unexpected: %v, %v", actual.Items[0], raindrop1)
	}
	if !reflect.DeepEqual(actual.Items[1], raindrop2) {
		t.Errorf("Unexpected: %v, %v", actual.Items[1], raindrop2)
	}
}

func Test_GetRootCollections(t *testing.T) {
	// Given
	collection1 := Collection{
		ID:    1,
		Title: "Test 1",
	}
	collection2 := Collection{
		ID:    2,
		Title: "Test 2",
	}
	expected := GetCollectionsResponse{
		Result: true,
		Items:  []Collection{collection1, collection2},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := json.Marshal(expected)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(res)
	}))

	defer ts.Close()

	// When
	sut := createTestClient(ts, t)

	// Then
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	actual, err := sut.GetRootCollections("access-token", ctx)
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if actual.Result != true {
		t.Error("actual.Result")
	}
	if len(actual.Items) != 2 {
		t.Errorf("Unexpected length: %d", len(actual.Items))
	}
	if !reflect.DeepEqual(actual.Items[0], collection1) {
		t.Errorf("Unexpected: %v, %v", actual.Items[0], collection1)
	}
	if !reflect.DeepEqual(actual.Items[1], collection2) {
		t.Errorf("Unexpected: %v, %v", actual.Items[1], collection2)
	}
}

func Test_GetChildCollections(t *testing.T) {
	// Given
	collection1 := Collection{
		ID:       1,
		Title:    "Test 1",
		ParentId: 1123,
	}
	collection2 := Collection{
		ID:       2,
		Title:    "Test 2",
		ParentId: 4543,
	}
	expected := GetCollectionsResponse{
		Result: true,
		Items:  []Collection{collection1, collection2},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := json.Marshal(expected)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(res)
	}))

	defer ts.Close()

	// When
	sut := createTestClient(ts, t)

	// Then
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	actual, err := sut.GetChildCollections("access-token", ctx)
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if actual.Result != true {
		t.Error("actual.Result")
	}
	if len(actual.Items) != 2 {
		t.Errorf("Unexpected length: %d", len(actual.Items))
	}
	if !reflect.DeepEqual(actual.Items[0], collection1) {
		t.Errorf("Unexpected: %v, %v", actual.Items[0], collection1)
	}
	if !reflect.DeepEqual(actual.Items[1], collection2) {
		t.Errorf("Unexpected: %v, %v", actual.Items[1], collection2)
	}
}

func Test_GetCollection(t *testing.T) {
	// Given
	collection1 := Collection{
		ID:    1,
		Title: "Test 1",
	}
	expected := GetCollectionResponse{
		Result: true,
		Item:   collection1,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := json.Marshal(expected)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(res)
	}))

	defer ts.Close()

	// When
	sut := createTestClient(ts, t)

	// Then
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	actual, err := sut.GetCollection("access-token", 1, ctx)
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if actual.Result != true {
		t.Error("actual.Result")
	}
	if !reflect.DeepEqual(actual.Item, collection1) {
		t.Errorf("Unexpected: %v, %v", actual.Item, collection1)
	}
}

func Test_CreateCollection(t *testing.T) {
	// Given
	collectionRequest := createCollectionRequest{
		View:     "list",
		Title:    "TestColl",
		Sort:     0,
		Public:   false,
		ParentId: 0,
		Cover:    nil,
	}
	expected := CreateCollectionResponse{
		Result: true,
		Item:   collectionRequest,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := json.Marshal(expected)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(res)
	}))

	defer ts.Close()

	// When
	sut := createTestClient(ts, t)

	// Then
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	actual, err := sut.CreateCollection("access-token", true, "list",
		"TestColl", 0, false, 0, nil, ctx)
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if actual.Result != true {
		t.Error("actual.Result")
	}
	if !reflect.DeepEqual(actual.Item, collectionRequest) {
		t.Errorf("Unexpected: %v, %v", actual.Item, collectionRequest)
	}
}

func Test_GetTags(t *testing.T) {
	// Given
	tag1 := Tag{
		ID:    "tag 1",
		Count: 10,
	}
	tag2 := Tag{
		ID:    "tag 2",
		Count: 100,
	}
	expected := Tags{
		Result: true,
		Items:  []Tag{tag1, tag2},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := json.Marshal(expected)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(res)
	}))

	defer ts.Close()

	// When
	sut := createTestClient(ts, t)

	// Then
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	actual, err := sut.GetTags("access-token", ctx)
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if actual.Result != true {
		t.Error("actual.Result")
	}
	if len(actual.Items) != 2 {
		t.Errorf("Unexpected length: %d", len(actual.Items))
	}
	if !reflect.DeepEqual(actual.Items[0], tag1) {
		t.Errorf("Unexpected: %v, %v", actual.Items[0], tag1)
	}
	if !reflect.DeepEqual(actual.Items[1], tag2) {
		t.Errorf("Unexpected: %v, %v", actual.Items[1], tag2)
	}
}

func Test_GetTaggedRaindrops(t *testing.T) {
	// Given
	raindrop1 := Raindrop{
		RaindropUserInfo: RaindropUserInfo{
			Tags:  []string{"foo", "bar"},
			Title: "Test 1",
			Link:  "https://example.com/1",
		},
	}
	expected := MultiRaindropsResponse{
		Result: true,
		Items:  []Raindrop{raindrop1},
	}
	tag := "tag 1"
	expectedQuery := `[{"key":"tag","val":"tag 1"}]`
	var actualQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := json.Marshal(expected)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		actualQuery = r.URL.Query().Get("search")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(res)
	}))

	defer ts.Close()

	// When
	sut := createTestClient(ts, t)

	// Then
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	actual, err := sut.GetTaggedRaindrops("access-token", tag, ctx)
	if err != nil {
		t.Errorf("error: %v", err)
	}
	if actualQuery != expectedQuery {
		t.Errorf("Unexpected: %v, %v", actualQuery, expectedQuery)
	}
	if actual.Result != true {
		t.Error("actual.Result")
	}
	if len(actual.Items) != 1 {
		t.Errorf("Unexpected length: %d", len(actual.Items))
	}
	if !reflect.DeepEqual(actual.Items[0], raindrop1) {
		t.Errorf("Unexpected: %v, %v", actual.Items[0], raindrop1)
	}
}

func createTestClient(ts *httptest.Server, t *testing.T) Client {
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Errorf("error: %v", err)
	}

	return Client{
		apiURL:     u,
		httpClient: &http.Client{},
	}
}
