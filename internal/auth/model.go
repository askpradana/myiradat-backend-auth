package auth

import "time"

type Profile struct {
	ID         int    `gorm:"primaryKey;autoIncrement"`
	Name       string `gorm:"size:255"`
	Email      string `gorm:"size:255;unique;not null"`
	NoHP       string `gorm:"size:255"`
	Password   string `gorm:"size:255;not null"`
	IsDeleted  bool
	CreatedAt  time.Time
	CreatedBy  string
	ModifiedAt time.Time
	ModifiedBy string
}

type ServiceModel struct {
	ID          int    `gorm:"primaryKey;autoIncrement"`
	ServiceName string `gorm:"type:text"`
	RedirectURI string `gorm:"type:text"`
	IsDeleted   bool
	CreatedAt   time.Time
	CreatedBy   string
	ModifiedAt  time.Time
	ModifiedBy  string
}

type Role struct {
	ID              int    `gorm:"primaryKey;autoIncrement"`
	RoleName        string `gorm:"size:255"`
	Description     string `gorm:"type:text"`
	MasterServiceID int
	IsDeleted       bool
	CreatedAt       time.Time
	CreatedBy       string
	ModifiedAt      time.Time
	ModifiedBy      string
}

type ProfileServiceRole struct {
	ProfileID int `gorm:"primaryKey"`
	ServiceID int `gorm:"primaryKey"`
	RoleID    int

	Profile Profile      `gorm:"foreignKey:ProfileID"`
	Service ServiceModel `gorm:"foreignKey:ServiceID"`
	Role    Role         `gorm:"foreignKey:RoleID"`
}
