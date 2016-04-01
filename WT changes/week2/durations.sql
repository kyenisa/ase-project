
ALTER TABLE durations
	ADD COLUMN user_agent TEXT,
	ADD COLUMN start BIGINT,
	ADD COLUMN pnow BIGINT,
	ADD COLUMN timing TEXT;	-- or JSON
	
