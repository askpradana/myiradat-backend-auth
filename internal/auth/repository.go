package auth

import (
	"errors"

	"gorm.io/gorm"
)

type Repository interface {
	CreateProfileWithRoles(profile *Profile, services []ServiceRoleRequest) error
	IsEmailExist(email string) bool
}

type repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) Repository {
	return &repository{db}
}

func (r *repository) IsEmailExist(email string) bool {
	var count int64
	r.db.Model(&Profile{}).Where("email = ?", email).Count(&count)
	return count > 0
}

func (r *repository) CreateProfileWithRoles(profile *Profile, services []ServiceRoleRequest) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(profile).Error; err != nil {
			return err
		}

		for _, s := range services {
			// Validate service + role relation
			var validRole bool
			err := tx.Raw(`
				SELECT EXISTS (
					SELECT 1 FROM roles WHERE id = ? AND master_service_id = ?
				)`, s.RoleID, s.ServiceID).Scan(&validRole).Error

			if err != nil || !validRole {
				return errors.New("invalid service and roles")
			}

			err = tx.Exec(`
				INSERT INTO profile_service_roles (profile_id, service_id, role_id)
				VALUES (?, ?, ?)`,
				profile.ID, s.ServiceID, s.RoleID,
			).Error

			if err != nil {
				return err
			}
		}

		return nil
	})
}
