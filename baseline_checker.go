package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	baselineFeaturesURL = "https://raw.githubusercontent.com/web-platform-dx/web-features/main/feature-group-definitions/baseline.json"
	updateInterval      = 24 * time.Hour
)

// BaselineFeature represents a single feature from the web-features dataset.
type BaselineFeature struct {
	Identifier string `json:"identifier"`
	MdnURL     string `json:"mdn_url"`
}

// BaselineChecker holds the set of baseline features for quick lookups.
type BaselineChecker struct {
	cssProperties  map[string]BaselineFeature
	jsAPIs         map[string]BaselineFeature
	htmlElements   map[string]BaselineFeature
	htmlAttributes map[string]BaselineFeature // Global attributes
	lastUpdated    time.Time
	mutex          sync.RWMutex
	stopChan       chan struct{}
}

// NewBaselineChecker initializes the checker and starts periodic updates.
func NewBaselineChecker(ctx context.Context) *BaselineChecker {
	bc := &BaselineChecker{
		cssProperties:  make(map[string]BaselineFeature),
		jsAPIs:         make(map[string]BaselineFeature),
		htmlElements:   make(map[string]BaselineFeature),
		htmlAttributes: make(map[string]BaselineFeature),
		stopChan:       make(chan struct{}),
	}
	return bc
}

// ensureFeaturesLoaded ensures that baseline features are loaded before use
func (bc *BaselineChecker) ensureFeaturesLoaded() {
	bc.mutex.RLock()
	featuresLoaded := len(bc.cssProperties) > 0 || len(bc.jsAPIs) > 0 || len(bc.htmlElements) > 0
	bc.mutex.RUnlock()

	if !featuresLoaded {
		log.Println("🔄 Loading Baseline web features for the first time...")
		bc.updateFeatures()
	}
}

// updateFeatures fetches the latest Baseline feature set.
func (bc *BaselineChecker) updateFeatures() {
	log.Println("🔄 Updating Baseline web features...")
	resp, err := http.Get(baselineFeaturesURL)
	if err != nil {
		log.Printf("⚠️  Failed to fetch Baseline features: %v", err)
		return
	}
	defer resp.Body.Close()

	// Check if response is successful
	if resp.StatusCode != http.StatusOK {
		log.Printf("⚠️  Failed to fetch Baseline features: HTTP %d", resp.StatusCode)
		return
	}

	var payload struct {
		Features []struct {
			Identifier string `json:"identifier"`
			MdnUrl     string `json:"mdn_url"`
		} `json:"features"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		log.Printf("⚠️  Failed to parse Baseline features JSON: %v", err)
		return
	}

	// Validate that we got features data
	if len(payload.Features) == 0 {
		log.Printf("⚠️  No features found in Baseline data")
		return
	}

	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// Clear old data
	bc.cssProperties = make(map[string]BaselineFeature)
	bc.jsAPIs = make(map[string]BaselineFeature)
	bc.htmlElements = make(map[string]BaselineFeature)
	bc.htmlAttributes = make(map[string]BaselineFeature)

	for _, f := range payload.Features {
		identifier := f.Identifier
		feature := BaselineFeature{Identifier: identifier, MdnURL: f.MdnUrl}

		if strings.HasPrefix(identifier, "css.properties.") {
			// e.g., css.properties.border-radius -> border-radius
			prop := strings.TrimPrefix(identifier, "css.properties.")
			bc.cssProperties[prop] = feature
		} else if strings.HasPrefix(identifier, "api.") {
			// e.g., api.Fetch -> Fetch
			api := strings.TrimPrefix(identifier, "api.")
			bc.jsAPIs[api] = feature
		} else if strings.HasPrefix(identifier, "html.elements.") {
			// e.g., html.elements.a -> a
			element := strings.TrimPrefix(identifier, "html.elements.")
			if !strings.Contains(element, ".attributes.") {
				bc.htmlElements[element] = feature
			}
		} else if strings.HasPrefix(identifier, "html.global_attributes.") {
			// e.g., html.global_attributes.hidden -> hidden
			attr := strings.TrimPrefix(identifier, "html.global_attributes.")
			bc.htmlAttributes[attr] = feature
		}
	}

	bc.lastUpdated = time.Now()
	log.Printf("✅ Baseline features updated. Found %d CSS properties, %d JS APIs, %d HTML elements.", len(bc.cssProperties), len(bc.jsAPIs), len(bc.htmlElements))
}

// startPeriodicUpdates runs updateFeatures immediately and then on a ticker.
func (bc *BaselineChecker) startPeriodicUpdates(ctx context.Context) {
	bc.updateFeatures() // Initial fetch
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bc.updateFeatures()
		case <-ctx.Done():
			return
		case <-bc.stopChan:
			return
		}
	}
}

// Stop halts the periodic updates.
func (bc *BaselineChecker) Stop() {
	close(bc.stopChan)
}

// IsCSSPropertyBaseline checks if a CSS property is in the Baseline set.
func (bc *BaselineChecker) GetCSSProperty(property string) (BaselineFeature, bool) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()
	feature, exists := bc.cssProperties[strings.ToLower(property)]
	return feature, exists
}

// IsJSAPIBaseline checks if a JavaScript API is in the Baseline set.
func (bc *BaselineChecker) GetJSAPI(api string) (BaselineFeature, bool) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()
	feature, exists := bc.jsAPIs[api]
	return feature, exists
}

// GetHTMLElement checks if an HTML element is in the Baseline set.
func (bc *BaselineChecker) GetHTMLElement(element string) (BaselineFeature, bool) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()
	feature, exists := bc.htmlElements[strings.ToLower(element)]
	return feature, exists
}
