package auth

import (
	"errors"

	"gorm.io/gorm"
)

type Repository interface {
	CreateProfileWithRoles(profile *Profile, services []ServiceRoleRequest) error
	IsEmailExist(email string) bool
	FindProfileByEmail(user *Profile, email string) error
	FindRolesByProfileID(profileID uint) ([]ServiceRoleResponse, error)
	UpdateUserPassword(user *Profile) error
	UpdateRefreshToken(userID uint, refreshToken string) error
	ClearRefreshTokenByEmail(email string) error
	FindActiveServiceRoles() ([]ServiceModel, error)
	FindRolesByServiceID(serviceID int) ([]Role, error)
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
	return r.db.
		Where("email = ? AND is_deleted = false", email).
		First(user).Error
}

func (r *repository) FindRolesByProfileID(profileID uint) ([]ServiceRoleResponse, error) {
	var result []ServiceRoleResponse

	err := r.db.
		Table("profile_service_roles AS psr").
		Select(`
			s.service_name AS service_name,
			s.redirect_uri AS redirect_uri,
			s.id AS service_id,
			r.id AS role_id,
			r.role_name AS role_name,
			r.description AS role_description
		`).
		Joins("JOIN services s ON s.id = psr.service_id AND s.is_deleted = FALSE").
		Joins("JOIN roles r ON r.id = psr.role_id AND r.is_deleted = FALSE").
		Where("psr.profile_id = ?", profileID).
		Scan(&result).Error

	return result, err
}

func (r *repository) UpdateUserPassword(user *Profile) error {
	return r.db.Model(&Profile{}).
		Where("email = ?", user.Email).
		Updates(map[string]interface{}{
			"password":    user.Password,
			"modified_at": user.ModifiedAt,
			"modified_by": user.ModifiedBy,
		}).Error
}

func (r *repository) UpdateRefreshToken(userID uint, refreshToken string) error {
	return r.db.Model(&Profile{}).
		Where("id = ?", userID).
		Update("refresh_token", refreshToken).Error
}

func (r *repository) ClearRefreshTokenByEmail(email string) error {
	return r.db.Model(&Profile{}).
		Where("email = ?", email).
		Update("refresh_token", "").Error
}

func (r *repository) FindActiveServiceRoles() ([]ServiceModel, error) {
	var services []ServiceModel
	err := r.db.
		Where("is_deleted = false").
		Find(&services).Error
	return services, err
}

func (r *repository) FindRolesByServiceID(serviceID int) ([]Role, error) {
	var roles []Role
	err := r.db.
		Where("master_service_id = ? AND is_deleted = false", serviceID).
		Find(&roles).Error
	return roles, err
}
