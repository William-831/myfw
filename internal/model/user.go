package model

import "time"

// User 平台登录用户。密码以 sha256(salt+password) 存储;
// 库中无记录时回退默认 admin/admin123(向后兼容)。
type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex;size:64;not null" json:"username"`
	PasswordHash string    `gorm:"size:128;not null" json:"-"`
	Salt         string    `gorm:"size:64;not null" json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
