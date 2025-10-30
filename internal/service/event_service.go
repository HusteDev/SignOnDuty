package service

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/thana/signonduty/internal/model"
	"github.com/thana/signonduty/internal/repository"
)

// EventService handles event business logic
type EventService struct {
	eventRepo *repository.EventRepository
}

func NewEventService(eventRepo *repository.EventRepository) *EventService {
	return &EventService{eventRepo: eventRepo}
}

// CreateEvent creates a new event
func (s *EventService) CreateEvent(event *model.Event) error {
	if event.Name == "" {
		return fmt.Errorf("event name is required")
	}

	if event.StartDate.IsZero() {
		return fmt.Errorf("event start date is required")
	}

	if event.OrganizerUID == "" {
		return fmt.Errorf("organizer UID is required")
	}

	// Validate signing method
	if event.SigningMethod != "mtls" && event.SigningMethod != "pades" && event.SigningMethod != "both" {
		event.SigningMethod = "both" // Default to both
	}

	return s.eventRepo.CreateEvent(event)
}

// GetEventByID retrieves an event
func (s *EventService) GetEventByID(eventID uuid.UUID) (*model.Event, error) {
	return s.eventRepo.GetEventByID(eventID)
}

// ListEvents lists all active events
func (s *EventService) ListEvents() ([]*model.Event, error) {
	return s.eventRepo.ListEvents()
}

// UpdateEvent updates an event
func (s *EventService) UpdateEvent(event *model.Event) error {
	// For now, just basic validation
	if event.ID == uuid.Nil {
		return fmt.Errorf("event ID is required")
	}

	return nil // Would update in database
}

// IsEventActive checks if an event is currently accepting signups
func (s *EventService) IsEventActive(event *model.Event) bool {
	now := time.Now().UTC()

	if !event.IsActive {
		return false
	}

	if now.Before(event.StartDate) {
		return false
	}

	if event.EndDate != nil && now.After(*event.EndDate) {
		return false
	}

	return true
}
