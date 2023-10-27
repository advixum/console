package models

import (
	"gorm.io/gorm"
)

type Users struct {
	gorm.Model
	User string `gorm:"not null"`
}
