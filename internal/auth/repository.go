package auth

import (
	"errors"

	"gorm.io/gorm"
)

type Repository interface {
	CreateProfileWithRoles(profile *Profile, services []ServiceRoleRequest) error
	IsEmailExist(email string) bool
	FindProfileByEmail(user *Profile, email string) error
	FindRolesByProfileID(profileID int) ([]ServiceRoleResponse, error)
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
		// Step 1: Create profile
		if err := tx.Create(profile).Error; err != nil {
			return err
		}

		// Step 2: Loop through service-role pairs
		for _, s := range services {
			var validRoleService bool
			err := tx.Raw(`--name: service-role pairs
				SELECT EXISTS (
					SELECT 1
					FROM roles r
					JOIN services s ON s.id = r.master_service_id
					WHERE r.id = ? AND s.id = ? AND r.is_deleted = FALSE AND s.is_deleted = FALSE
				)
			`, s.RoleID, s.ServiceID).Scan(&validRoleService).Error

			if err != nil || !validRoleService {
				return errors.New("invalid service and roles")
			}

			// Step 3: Insert mapping
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

func (r *repository) FindProfileByEmail(user *Profile, email string) error {
	return r.db.Where("email = ?", email).First(user).Error
}

func (r *repository) FindRolesByProfileID(profileID int) ([]ServiceRoleResponse, error) {
	var result []ServiceRoleResponse

	err := r.db.Raw(`
		SELECT s.service_name, r.role_name
		FROM profile_service_roles psr
		JOIN services s ON s.id = psr.service_id
		JOIN roles r ON r.id = psr.role_id AND r.master_service_id = s.id
		WHERE psr.profile_id = ?`, profileID).Scan(&result).Error

	return result, err
}
