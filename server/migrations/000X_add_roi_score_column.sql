-- Add ROI score column to target_urls table
ALTER TABLE target_urls ADD COLUMN roi_score INTEGER NOT NULL DEFAULT 50; 