package db

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// --- Models ---

type Route struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	Hostname     string `gorm:"uniqueIndex;not null" json:"hostname"`
	TargetURL    string `gorm:"not null" json:"target_url"`
	TLSEnabled   bool   `gorm:"default:true" json:"tls_enabled"`
	AuthType     string `gorm:"default:none" json:"auth_type"`
	AuthConfig   string `gorm:"default:{}" json:"auth_config"`
	PreserveHost bool   `gorm:"default:false" json:"preserve_host"`
	Enabled      bool   `gorm:"default:true" json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Cert struct {
	Hostname  string    `gorm:"primaryKey" json:"hostname"`
	CertPEM   string    `json:"cert_pem,omitempty"`
	KeyPEM    string    `json:"key_pem,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	IsStaging bool      `gorm:"default:false" json:"is_staging"`
}

type APIKey struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"not null" json:"name"`
	KeyHash   string    `gorm:"uniqueIndex;not null" json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type HealthCheck struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	RouteID   uint      `gorm:"index;not null" json:"route_id"`
	Status    int       `gorm:"not null" json:"status"`
	LatencyMs int       `gorm:"not null" json:"latency_ms"`
	CheckedAt time.Time `gorm:"autoCreateTime" json:"checked_at"`
}

type ACMEAccount struct {
	Email        string `gorm:"primaryKey" json:"email"`
	KeyPEM       string `gorm:"not null" json:"key_pem"`
	Registration string `gorm:"not null" json:"registration"`
}

type Replica struct {
	ID       string `gorm:"primaryKey" json:"id"`
	Name     string `gorm:"not null" json:"name"`
	URL      string `gorm:"not null" json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Mode     string `gorm:"default:rewrites" json:"mode"`
}

type Setting struct {
	Key   string `gorm:"primaryKey" json:"key"`
	Value string `gorm:"not null" json:"value"`
}

// --- Database ---

type DB struct {
	G *gorm.DB
}

func Open(path string) (*DB, error) {
	g, err := gorm.Open(sqlite.Open(path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	sqlDB, _ := g.DB()
	sqlDB.SetMaxOpenConns(1)

	if err := g.AutoMigrate(&Route{}, &Cert{}, &APIKey{}, &HealthCheck{}, &ACMEAccount{}, &Replica{}, &Setting{}); err != nil {
		return nil, err
	}

	return &DB{G: g}, nil
}

func (d *DB) Close() error {
	sqlDB, err := d.G.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// --- Routes ---

func (d *DB) ListRoutes() ([]Route, error) {
	var routes []Route
	err := d.G.Order("hostname").Find(&routes).Error
	return routes, err
}

func (d *DB) GetRoute(id uint) (*Route, error) {
	var r Route
	err := d.G.First(&r, id).Error
	return &r, err
}

func (d *DB) GetRouteByHostname(hostname string) (*Route, error) {
	var r Route
	err := d.G.Where("hostname = ? AND enabled = ?", hostname, true).First(&r).Error
	return &r, err
}

func (d *DB) CreateRoute(r *Route) error {
	if r.AuthConfig == "" {
		r.AuthConfig = "{}"
	}
	if r.AuthType == "" {
		r.AuthType = "none"
	}
	return d.G.Create(r).Error
}

func (d *DB) UpdateRoute(r *Route) error {
	return d.G.Save(r).Error
}

func (d *DB) DeleteRoute(id uint) error {
	return d.G.Delete(&Route{}, id).Error
}

// --- Certs ---

func (d *DB) ListCerts() ([]Cert, error) {
	var certs []Cert
	err := d.G.Select("hostname", "not_before", "not_after", "is_staging").Order("hostname").Find(&certs).Error
	return certs, err
}

func (d *DB) GetCert(hostname string) (*Cert, error) {
	var c Cert
	err := d.G.Where("hostname = ?", hostname).First(&c).Error
	return &c, err
}

func (d *DB) UpsertCert(c *Cert) error {
	return d.G.Save(c).Error
}

func (d *DB) ExpiringCerts(within time.Duration) ([]Cert, error) {
	var certs []Cert
	deadline := time.Now().Add(within)
	err := d.G.Where("not_after < ?", deadline).Find(&certs).Error
	return certs, err
}

// --- API Keys ---

func (d *DB) CreateAPIKey(name, keyHash string) error {
	return d.G.Create(&APIKey{Name: name, KeyHash: keyHash}).Error
}

func (d *DB) APIKeyExists(keyHash string) (bool, error) {
	var count int64
	err := d.G.Model(&APIKey{}).Where("key_hash = ?", keyHash).Count(&count).Error
	return count > 0, err
}

func (d *DB) HasAnyAPIKey() (bool, error) {
	var count int64
	err := d.G.Model(&APIKey{}).Count(&count).Error
	return count > 0, err
}

// --- Health Checks ---

func (d *DB) InsertHealthCheck(routeID uint, status, latencyMs int) error {
	if err := d.G.Create(&HealthCheck{RouteID: routeID, Status: status, LatencyMs: latencyMs}).Error; err != nil {
		return err
	}
	// Trim to 100 per route
	d.G.Exec(`DELETE FROM health_checks WHERE route_id = ? AND id NOT IN (SELECT id FROM health_checks WHERE route_id = ? ORDER BY checked_at DESC LIMIT 100)`, routeID, routeID)
	return nil
}

func (d *DB) GetHealthChecks(routeID uint) ([]HealthCheck, error) {
	var checks []HealthCheck
	err := d.G.Where("route_id = ?", routeID).Order("checked_at DESC").Limit(100).Find(&checks).Error
	return checks, err
}

// --- ACME Accounts ---

func (d *DB) GetACMEAccount(email string) (*ACMEAccount, error) {
	var a ACMEAccount
	err := d.G.Where("email = ?", email).First(&a).Error
	return &a, err
}

func (d *DB) UpsertACMEAccount(a *ACMEAccount) error {
	return d.G.Save(a).Error
}

// --- Replicas ---

func (d *DB) ListReplicas() ([]Replica, error) {
	var replicas []Replica
	err := d.G.Find(&replicas).Error
	return replicas, err
}

func (d *DB) CreateReplica(r *Replica) error {
	return d.G.Create(r).Error
}

func (d *DB) UpdateReplica(r *Replica) error {
	return d.G.Save(r).Error
}

func (d *DB) DeleteReplica(id string) error {
	return d.G.Delete(&Replica{}, "id = ?", id).Error
}

// --- Settings ---

func (d *DB) GetSetting(key string) string {
	var s Setting
	if d.G.Where("key = ?", key).First(&s).Error == nil {
		return s.Value
	}
	return ""
}

func (d *DB) SetSetting(key, value string) error {
	return d.G.Save(&Setting{Key: key, Value: value}).Error
}

// --- Counts ---

func (d *DB) RouteCount() (int64, error) {
	var count int64
	err := d.G.Model(&Route{}).Count(&count).Error
	return count, err
}

func (d *DB) CertCount() (int64, error) {
	var count int64
	err := d.G.Model(&Cert{}).Count(&count).Error
	return count, err
}

func (d *DB) ReplicaCount() (int64, error) {
	var count int64
	err := d.G.Model(&Replica{}).Count(&count).Error
	return count, err
}
